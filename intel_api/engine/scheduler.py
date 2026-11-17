"""Runs the background jobs (engine/jobs.py) when they are due. One job at a time, so the sources
are never hit by two collections at once; any job can also be triggered on demand (POST /v1/admin/refresh)."""

import sys
import threading
import time

from . import jobs

TICK = 30


def log(msg):
    print(f"{time.strftime('%H:%M:%S')} [intel-api] {msg}", file=sys.stderr, flush=True)


def due(store):
    return [j for j in jobs.all_jobs() if j.due(store)]


def run(store, key):
    job = jobs.get(key)
    if job is None:
        raise KeyError(key)
    return jobs.run_job(store, job, log)


def run_due(store):
    return [jobs.run_job(store, j, log) for j in due(store)]


class Scheduler(threading.Thread):
    def __init__(self, store):
        super().__init__(daemon=True, name="intel-scheduler")
        self.store, self.stop = store, threading.Event()
        self.busy = threading.Lock()
        self.wake = threading.Event()

    def trigger(self, key=None):
        """Run one job (or everything due) now, in the background."""

        def go():
            with self.busy:
                try:
                    if key:
                        run(self.store, key)
                    else:
                        run_due(self.store)
                except Exception as e:  # noqa: BLE001 - a background thread: log, don't die silently
                    log(f"triggered run of {key or 'everything due'} failed: {type(e).__name__}: {e}")

        threading.Thread(target=go, daemon=True).start()

    def run(self):
        while not self.stop.is_set():
            with self.busy:
                try:
                    for j in due(self.store):
                        if self.stop.is_set():
                            break
                        jobs.run_job(self.store, j, log)
                except Exception as e:  # noqa: BLE001 - e.g. the database or scope.json is unreadable for a moment:
                    # without this the scheduler thread would die and no background job would run again
                    log(f"scheduler: {type(e).__name__}: {e}; trying again in {TICK}s")
            self.wake.wait(TICK)
            self.wake.clear()
