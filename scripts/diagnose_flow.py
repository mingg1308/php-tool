"""Trace file initialization; CPU-profile summary construction with a time budget."""
import _thread
import cProfile
import json
from pathlib import Path
import pstats
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from php_deserial_sast.cli import main
from php_deserial_sast.core.dataflow import FileFlow, FlowProject


def interrupt_with_snapshot():
    frame = sys._current_frames().get(threading.main_thread().ident)
    rows = []
    while frame is not None:
        row = {'function': frame.f_code.co_name, 'line': frame.f_lineno}
        function = frame.f_locals.get('f')
        if hasattr(function, 'engine') and hasattr(function, 'node'):
            row['php_function'] = function.name
            row['php_file'] = function.engine.path
            row['php_line'] = function.node.start_point[0] + 1
        for name in ('flows', 'sinks', 'result', 'found', 'effects'):
            value = frame.f_locals.get(name)
            if isinstance(value, (tuple, list, dict)):
                row[name + '_count'] = len(value)
        rows.append(row)
        frame = frame.f_back
    print('INTERRUPT_STACK', json.dumps(rows), flush=True)
    _thread.interrupt_main()

if __name__ == '__main__':
    whole_scan = "--whole-scan" in sys.argv
    if whole_scan:
        sys.argv.remove("--whole-scan")
    after_summary = "--after-summary" in sys.argv
    if after_summary:
        sys.argv.remove("--after-summary")
    seconds, output = float(sys.argv[1]), Path(sys.argv[2])
    sys.argv = [sys.argv[0]] + sys.argv[3:]
    initialize, build = FileFlow.__init__, FlowProject.build
    profiler = cProfile.Profile()
    if after_summary:
        timer = None
        def start_after_summary(self, *args, **kwargs):
            global timer
            result = build(self, *args, **kwargs)
            print("SUMMARY_COMPLETE_PROFILE_FINDINGS", flush=True)
            timer = threading.Timer(seconds, interrupt_with_snapshot)
            timer.daemon = True
            timer.start()
            profiler.enable()
            return result
        FlowProject.build = start_after_summary
        try:
            main()
        finally:
            if timer is not None:
                timer.cancel()
            profiler.disable()
            profiler.dump_stats(str(output))
            pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(40)
        raise SystemExit(0)
    if whole_scan:
        timer = threading.Timer(seconds, interrupt_with_snapshot)
        timer.daemon = True
        timer.start()
        try:
            profiler.runcall(main)
        finally:
            timer.cancel()
            profiler.dump_stats(str(output))
            pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(40)
        raise SystemExit(0)

    def traced_init(self, project, path, root, source):
        start = time.perf_counter()
        print('FILE_START', path, flush=True)
        initialize(self, project, path, root, source)
        print('FILE_DONE', path, round(time.perf_counter()-start, 3), flush=True)

    def profiled_build(self, *args, **kwargs):
        print('SUMMARY_START', flush=True)
        timer = threading.Timer(seconds, interrupt_with_snapshot)
        timer.daemon = True
        timer.start()
        try:
            return profiler.runcall(build, self, *args, **kwargs)
        finally:
            timer.cancel()
            sizes = sorted(((len(sinks), len({s.key()[:7] for s in sinks}), key)
                            for key, sinks in self.sinks.items()), reverse=True)[:12]
            print('SUMMARY_CARDINALITY', json.dumps(sizes), flush=True)
            profiler.dump_stats(str(output))
            pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(30)

    FileFlow.__init__ = traced_init
    FlowProject.build = profiled_build
    main()
