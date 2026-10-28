"""Bound external analyzers across host suspend/resume as well as normal waits."""
import subprocess
import time


def run_bounded(command, *, stdout, stderr, timeout, stop, clock=time.time):
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    deadline = clock() + timeout
    process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    try:
        while True:
            remaining = deadline - clock()
            if remaining <= 0:
                try:
                    stop()
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=10)
                return "timeout", None
            try:
                # Windows process waits may exclude suspended time. Recheck
                # wall time at least every second after the host resumes.
                code = process.wait(timeout=min(1.0, remaining))
                return "finished", code
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
