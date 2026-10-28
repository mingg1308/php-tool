"""Bounded CPU profile of the CLI; interruption does not produce a valid scan."""
import _thread
import cProfile
from pathlib import Path
import pstats
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from php_deserial_sast.cli import main

if __name__ == '__main__':
    seconds, output = float(sys.argv[1]), Path(sys.argv[2])
    sys.argv = [sys.argv[0]] + sys.argv[3:]
    timer = threading.Timer(seconds, _thread.interrupt_main)
    timer.daemon = True
    profiler = cProfile.Profile()
    timer.start()
    try:
        profiler.runcall(main)
    except KeyboardInterrupt:
        print('Profile interrupted at time budget; this is not a completed scan.')
    finally:
        timer.cancel()
        profiler.dump_stats(str(output))
        pstats.Stats(profiler).strip_dirs().sort_stats('cumulative').print_stats(35)
