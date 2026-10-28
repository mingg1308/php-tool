"""Statement CFG for branch/termination reachability, not a full PHP solver.

Unsupported control flow disables pruning for the whole lexical scope.
While/do backedges support variable reaching definitions. Predicates, aliasing
and exception handlers remain unmodeled.
"""
from collections import defaultdict, deque
from php_deserial_sast.core.bindings import foreach_bindings

SCOPES = {"function_definition", "method_declaration", "anonymous_function",
          "anonymous_function_creation_expression", "arrow_function"}
DECLARATIONS = SCOPES | {"class_declaration", "trait_declaration", "interface_declaration", "enum_declaration"}
# Literal payloads cannot contain reads, writes or control transfers. Font
# tables may contain millions of them; no CFG location is needed for each.
LITERALS = {"integer", "float", "boolean", "null", "string", "name",
            "qualified_name", "string_content", "escape_sequence", "comment"}
CFG_NODE_LIMIT = 5000
FOREACH_CFG_NODE_LIMIT = 256
UNSUPPORTED = {"goto_statement", "named_label_statement",
               "yield_expression", "yield_from_expression",
               "ERROR"}


class ScopeCFG:
    def __init__(self, body, experimental_foreach_cfg=False):
        self.edges = defaultdict(set)
        self.locations = {}
        self.kinds = {0: "entry"}
        self.unsupported = set()
        self._reach_masks = {}
        self._avoid_masks = {}
        self._definitions = {}
        self.definition_evaluations = 0
        self.has_loops = False
        self._loops = []
        self._exception_targets = []
        self._finalizers = []
        self._target_depth = {}
        self.has_exceptions = False
        self.normal_exits = set()
        self._header_writes = set()
        self._iteration_writes = set()
        stack = [body]
        visited = 0
        contains_foreach = False
        while stack:
            current = stack.pop()
            visited += 1
            if visited > CFG_NODE_LIMIT:
                self.unsupported.add("cfg_node_budget")
                break
            if current.type in DECLARATIONS or current.type in LITERALS:
                continue
            if current.type in UNSUPPORTED:
                self.unsupported.add(current.type)
            if current.type == "foreach_statement":
                contains_foreach = True
                if not experimental_foreach_cfg:
                    self.unsupported.add("foreach_cfg_disabled")
                if foreach_bindings(current) is None:
                    self.unsupported.add("foreach_binding")
            stack.extend(current.named_children)
        if contains_foreach and visited > FOREACH_CFG_NODE_LIMIT:
            self.unsupported.add("foreach_cfg_budget")
        self.supported = not self.unsupported
        if self.supported:
            try:
                self.normal_exits = self._statement(body, {0})
            except (RecursionError, ValueError) as exc:
                self.supported = False
                self.unsupported.add("cfg_nesting_limit" if isinstance(exc, RecursionError)
                                     else "unsupported_loop_jump")
                self.edges.clear()
                self.locations.clear()
                self.kinds = {0: "entry"}
        self.reachable = self._walk(0)
        self.predecessors = defaultdict(set)
        for previous, following in self.edges.items():
            for block in following:
                self.predecessors[block].add(previous)

    def effect_can_escape(self, origin, access, writes, normal_only=False):
        """Can a may-write escape without a definite overwrite?

        Exception/finally scopes and unmapped locations retain the effect.
        Only standalone assignments to the same storage or an ancestor kill.
        """
        start = self.locations.get(origin.id)
        if not self.supported or self.has_exceptions or start is None:
            return True
        kills = set()
        for write, target in writes:
            if (write.type == "assignment_expression" and write.parent is not None
                    and write.parent.type == "expression_statement"
                    and len(target) <= len(access) and None not in target
                    and target == access[:len(target)]):
                block = self.locations.get(write.id)
                if block is not None and block != start:
                    kills.add(block)
        # A caller's catch can observe writes made before a throw. Treat
        # terminal blocks conservatively, including expression-wrapped throw.
        exits = self.normal_exits | ({b for b in self.reachable if self.kinds.get(b) == "return_statement"}
                                     if normal_only else {b for b in self.reachable if not self.edges.get(b)})
        pending, seen = [start], set()
        while pending:
            block = pending.pop()
            if block in seen or block in kills:
                continue
            seen.add(block)
            if block in exits:
                return True
            pending.extend(self.edges.get(block, ()))
        return False

    def reaching_definitions(self, variable, writes, use):
        """GEN/KILL for standalone scalar writes; None means lexical fallback.

        -1 is the incoming value (parameter/global/uninitialized local).
        Return definitions at block entry, so x = x reads the previous value.
        Conditional expression writes and field writes are intentionally excluded.
        """
        block = self.locations.get(use.id)
        if not self.supported or block is None:
            return None
        if variable not in self._definitions:
            generated = {}
            for assignment, target in writes:
                ordinary = (assignment.type in {"assignment_expression", "augmented_assignment_expression"}
                            and assignment.parent is not None
                            and (assignment.parent.type == "expression_statement"
                                 or assignment.id in self._header_writes))
                if target != (variable,) or not (ordinary or assignment.id in self._iteration_writes):
                    self._definitions[variable] = None
                    break
                owner = self.locations.get(assignment.id)
                if owner is None or owner in generated:
                    self._definitions[variable] = None
                    break
                generated[owner] = assignment.id
            else:
                incoming = {node: frozenset() for node in self.reachable}
                outgoing = dict(incoming)
                queue = deque(sorted(self.reachable))
                pending = set(queue)
                while queue:
                    node = queue.popleft()
                    pending.remove(node)
                    self.definition_evaluations += 1
                    before = (frozenset({-1}) if node == 0 else
                              frozenset().union(*(outgoing.get(p, frozenset())
                                                  for p in self.predecessors[node])))
                    after = frozenset({generated[node]}) if node in generated else before
                    incoming[node] = before
                    if outgoing[node] != after:
                        outgoing[node] = after
                        for successor in sorted(self.edges.get(node, ())):
                            if successor not in pending:
                                queue.append(successor)
                                pending.add(successor)
                self._definitions[variable] = incoming
        mapping = self._definitions[variable]
        return None if mapping is None else mapping.get(block, frozenset())

    def _block(self, node, incoming, kind=None):
        block = len(self.kinds)
        self.kinds[block] = kind or node.type
        for previous in incoming:
            self.edges[previous].add(block)
        if self._exception_targets:
            # Overapproximate exceptions before or after a statement's write.
            for target in self._exception_targets[-1]:
                self.edges[block].add(target)
                for previous in incoming:
                    self.edges[previous].add(target)
        stack = [node] if node is not None else []
        while stack:
            current = stack.pop()
            if current.type in DECLARATIONS or current.type in LITERALS:
                continue
            self.locations[current.id] = block
            stack.extend(current.named_children)
        return block

    def _push_loop(self, exit_block, continue_block):
        self._loops.append((exit_block, continue_block))
        self._target_depth[exit_block] = self._target_depth[continue_block] = len(self._finalizers)

    def _abrupt(self, block, target=None):
        if self._finalizers and (target is None or self._target_depth.get(target, 0) < len(self._finalizers)):
            entry, completions = self._finalizers[-1]
            self.edges[block].add(entry)
            completions.add(target)
        elif target is not None:
            self.edges[block].add(target)

    def _expressions(self, node, incoming):
        """Comma-separated for clauses execute left to right, once per block."""
        if node is None:
            return incoming
        if node.type == "sequence_expression":
            for child in node.named_children:
                if child.type != "comment":
                    incoming = self._expressions(child, incoming)
            return incoming
        if node.type in {"assignment_expression", "augmented_assignment_expression"}:
            self._header_writes.add(node.id)
        return {self._block(node, incoming)}

    def _statement(self, node, incoming):
        if node is None or node.type in DECLARATIONS:
            return incoming
        if node.type in {"program", "compound_statement", "namespace_definition"}:
            for child in node.named_children:
                incoming = self._statement(child, incoming)
            return incoming
        if node.type == "if_statement":
            head = self._block(node, incoming, "branch")
            exits = self._statement(node.child_by_field_name("body"), {head})
            pending = {head}
            for clause in node.named_children:
                if clause.type == "else_if_clause":
                    branch = self._block(clause, pending, "branch")
                    exits |= self._statement(clause.child_by_field_name("body"), {branch})
                    pending = {branch}
                elif clause.type == "else_clause":
                    exits |= self._statement(clause.child_by_field_name("body"), pending)
                    pending = set()
            return exits | pending
        if node.type == 'try_statement':
            self.has_exceptions = True
            catches = [c for c in node.named_children if c.type == 'catch_clause']
            final = next((c for c in node.named_children if c.type == 'finally_clause'), None)
            outer = set(self._exception_targets[-1]) if self._exception_targets else set()
            entries = [self._block(None, set(), 'catch_entry') for c in catches]
            final_entry = self._block(None, set(), 'finally_entry') if final is not None else None
            completions = set()
            if final_entry is not None:
                self._finalizers.append((final_entry, completions))
            handlers = set(entries) | ({final_entry} if final_entry is not None else outer)
            self._exception_targets.append(handlers)
            exits = self._statement(node.child_by_field_name('body'), incoming)
            self._exception_targets.pop()
            self._exception_targets.append({final_entry} if final_entry is not None else outer)
            for catch, entry in zip(catches, entries):
                self.locations[catch.id] = entry
                exits |= self._statement(catch.child_by_field_name('body'), {entry})
            self._exception_targets.pop()
            if final_entry is None:
                return exits
            self._finalizers.pop()
            # Lexically trailing statements after return/throw still have CFG
            # blocks, but cannot turn an abrupt completion into a normal one.
            exits.intersection_update(self._walk(0))
            for previous in exits:
                self.edges[previous].add(final_entry)
            tail = self._statement(final.child_by_field_name('body'), {final_entry})
            for previous in tail:
                for target in completions:
                    self._abrupt(previous, target)
                for target in outer:
                    self.edges[previous].add(target)
            # Completion kinds share one finally body. This may retain extra
            # paths, but never omits execution of finally on abrupt completion.
            return tail if exits else set()
        if node.type == 'switch_statement':
            head = self._block(node.child_by_field_name('condition'), incoming, 'switch_condition')
            exit_block = self._block(None, set(), 'switch_exit')
            clauses = [c for c in node.child_by_field_name('body').named_children
                       if c.type in {'case_statement', 'default_statement'}]
            pending, entries, default = {head}, [], None
            for clause in clauses:
                entry = self._block(None, set(), 'case_body')
                entries.append(entry)
                self.locations[clause.id] = entry
                value = clause.child_by_field_name('value')
                if value is None:
                    default = entry
                else:
                    test = self._block(value, pending, 'case_test')
                    self.edges[test].add(entry)
                    pending = {test}
            for previous in pending:
                self.edges[previous].add(default if default is not None else exit_block)
            # PHP counts switch for jump levels; continue 1 exits switch.
            self._push_loop(exit_block, exit_block)
            tail = set()
            for clause, entry in zip(clauses, entries):
                for previous in tail:
                    self.edges[previous].add(entry)
                tail = {entry}
                value = clause.child_by_field_name('value')
                for child in clause.named_children:
                    if child != value and child.type != 'comment':
                        tail = self._statement(child, tail)
            self._loops.pop()
            for previous in tail:
                self.edges[previous].add(exit_block)
            return {exit_block}
        if node.type == "foreach_statement":
            self.has_loops = True
            parts = [c for c in node.named_children if c.type != "comment"]
            iterable, binding = parts[:2]
            # By-value iterable is evaluated once, before any binding writes.
            evaluated = self._block(iterable, incoming, "foreach_iterable")
            head = self._block(None, {evaluated}, "foreach_next")
            exit_block = self._block(None, {head}, "loop_exit")
            bound = self._block(binding, {head}, "foreach_binding")
            self.locations[node.id] = bound
            self._iteration_writes.add(node.id)
            self._push_loop(exit_block, head)
            tail = self._statement(node.child_by_field_name("body"), {bound})
            self._loops.pop()
            for previous in tail:
                self.edges[previous].add(head)
            return {exit_block}
        if node.type == "for_statement":
            self.has_loops = True
            incoming = self._expressions(node.child_by_field_name("initialize"), incoming)
            head = self._block(None, incoming, "for_condition_entry")
            condition = node.child_by_field_name("condition")
            tested = self._expressions(condition, {head})
            exit_block = self._block(None, set(), "loop_exit")
            if condition is not None:
                for previous in tested:
                    self.edges[previous].add(exit_block)
            update_entry = self._block(None, set(), "for_update_entry")
            self._push_loop(exit_block, update_entry)
            tail = self._statement(node.child_by_field_name("body"), tested)
            self._loops.pop()
            for previous in tail:
                self.edges[previous].add(update_entry)
            updated = self._expressions(node.child_by_field_name("update"), {update_entry})
            for previous in updated:
                self.edges[previous].add(head)
            return {exit_block}
        if node.type in {"while_statement", "do_statement"}:
            self.has_loops = True
            condition = node.child_by_field_name("condition")
            # Condition is a separate block: never map body definitions to it.
            head = self._block(condition, set(), "loop_condition")
            exit_block = len(self.kinds)
            self.kinds[exit_block] = "loop_exit"
            self.edges[head].add(exit_block)
            self._push_loop(exit_block, head)
            if node.type == "while_statement":
                for previous in incoming:
                    self.edges[previous].add(head)
                tail = self._statement(node.child_by_field_name("body"), {head})
                for previous in tail:
                    self.edges[previous].add(head)
            else:
                entry = len(self.kinds)
                self.kinds[entry] = "loop_body_entry"
                for previous in incoming:
                    self.edges[previous].add(entry)
                tail = self._statement(node.child_by_field_name("body"), {entry})
                for previous in tail:
                    self.edges[previous].add(head)
                self.edges[head].add(entry)
            self._loops.pop()
            return {exit_block}
        if node.type in {"break_statement", "continue_statement"}:
            children = node.named_children
            level = 1
            if children:
                # Only literal decimal levels are modeled. Other forms keep
                # the entire scope on conservative lexical analysis.
                value = children[0].text.decode("utf-8")
                if (len(children) != 1 or children[0].type != "integer"
                        or not value.isdecimal() or value.startswith("0")):
                    raise ValueError("unsupported loop jump level")
                level = int(value)
            if not 1 <= level <= len(self._loops):
                raise ValueError("loop jump outside modeled loop")
            block = self._block(node, incoming)
            target = self._loops[-level][int(node.type == "continue_statement")]
            self._abrupt(block, target)
            return set()
        block = self._block(node, incoming)
        if node.type in {"return_statement", "throw_statement", "throw_expression", "exit_statement"}:
            if node.type != 'exit_statement':
                self._abrupt(block)
            return set()
        if node.type == "expression_statement" and any(
            child.type == "throw_expression" for child in node.named_children
        ):
            self._abrupt(block)
            return set()
        return {block}

    def _walk(self, start, avoid=None):
        reached, pending = set(), [start]
        while pending:
            current = pending.pop()
            if current in reached or current == avoid:
                continue
            reached.add(current)
            pending.extend(self.edges.get(current, ()))
        return reached

    def is_reachable(self, node):
        block = self.locations.get(node.id)
        return not self.supported or block is None or block in self.reachable

    def may_reach(self, definition, use):
        if not self.supported:
            return True
        start, end = self.locations.get(definition.id), self.locations.get(use.id)
        if start is None or end is None:
            return True
        if start not in self.reachable or end not in self.reachable:
            return False
        if start not in self._reach_masks:
            self._reach_masks[start] = sum(1 << block for block in self._walk(start))
        return bool(self._reach_masks[start] & (1 << end))

    def dominates(self, definition, use):
        """Only lift dominance to AST definitions that execute as a whole block.

        An assignment inside a ternary/short-circuit expression is not an
        unconditional write just because its enclosing statement dominates.
        """
        if not self.supported:
            return None
        standalone_write = (
            definition.type in {"assignment_expression", "augmented_assignment_expression"}
            and definition.parent is not None
            and (definition.parent.type == "expression_statement"
                 or definition.id in self._header_writes)
        )
        if not standalone_write:
            return None
        start, end = self.locations.get(definition.id), self.locations.get(use.id)
        if start is None or end is None or start == end:
            return None
        if start not in self.reachable or end not in self.reachable:
            return False
        if start not in self._avoid_masks:
            self._avoid_masks[start] = sum(1 << block for block in self._walk(0, avoid=start))
        return not bool(self._avoid_masks[start] & (1 << end))


def coverage(project):
    counts = defaultdict(int)
    total = supported = blocks = variables = evaluations = loop_scopes = loop_iterations = exception_scopes = 0
    for engine in getattr(project, "files", {}).values():
        loop_iterations += engine.loop_iterations
        for cfg in engine.cfgs.values():
            total += 1
            supported += int(cfg.supported)
            loop_scopes += int(cfg.supported and cfg.has_loops)
            exception_scopes += int(cfg.supported and cfg.has_exceptions)
            blocks += len(cfg.kinds)
            variables += sum(mapping is not None for mapping in cfg._definitions.values())
            evaluations += cfg.definition_evaluations
            for reason in cfg.unsupported:
                counts[reason] += 1
    return {"mode": "statement_reachability", "scopes": total,
            "experimental_foreach_cfg": getattr(project, "experimental_foreach_cfg", False),
            "supported_scopes": supported, "fallback_scopes": total - supported,
            "blocks": blocks, "fallback_reasons": dict(sorted(counts.items())),
            "reaching_definitions": "standalone_scalar_writes",
            "definition_variables": variables, "definition_evaluations": evaluations,
            "loop_scopes": loop_scopes, "loop_iterations": loop_iterations,
            "exception_scopes": exception_scopes, "exception_model": "conservative_edges_and_merged_finally_completions",
            "predicate_solving": False, "loop_dataflow": "while_do_for_foreach_value_variables"}
