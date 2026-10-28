"""By-value foreach bindings and their paths into each iterable element."""
from enum import Enum


class FieldKind(Enum):
    ARRAY_KEY = 'array_key'


def foreach_bindings(node):
    parts = [c for c in node.named_children if c.type != 'comment']
    if len(parts) < 2:
        return None
    binding = parts[1]

    def unpack(current, path):
        if current.type == 'variable_name':
            return [(current, path)]
        if current.type != 'list_literal':
            return None
        slots, slot = [], []
        for child in current.children:
            if child.type in {'[', ']', '(', ')', 'list', 'comment'}:
                continue
            if child.type == ',':
                slots.append(slot)
                slot = []
            else:
                slot.append(child)
        slots.append(slot)
        result = []
        for index, slot in enumerate(slots):
            if not slot:
                continue
            key, value = str(index), slot[-1]
            if len(slot) == 3 and slot[1].type == '=>':
                literal = slot[0]
                if literal.type == 'integer':
                    key = literal.text.decode('utf-8')
                elif literal.type == 'string' and all(c.type == 'string_content' for c in literal.named_children):
                    key = literal.text.decode('utf-8')[1:-1]
                else:
                    return None
            elif len(slot) != 1:
                return None
            nested = unpack(value, path + (key,))
            if nested is None:
                return None
            result.extend(nested)
        return result

    if binding.type == 'pair':
        pair = [c for c in binding.named_children if c.type != 'comment']
        if len(pair) != 2 or pair[0].type != 'variable_name':
            return None
        values = unpack(pair[1], (None,))
        return None if values is None else [(pair[0], (FieldKind.ARRAY_KEY,))] + values
    return unpack(binding, (None,))
