"""Bounded job queue + fixed pool of worker threads (concurrency = CG_WORKERS, queue size = CG_QUEUE_MAX).

Restart semantics (see README): on startup, jobs left `running` are marked `failed` with
error "interrupted by server restart" (partial stage output is not trusted); jobs still `queued` are re-enqueued."""
from __future__ import annotations

import logging
import queue
import threading

log = logging.getLogger("chainguard.worker")


class QueueFull(Exception):
    pass


class JobWorker:
    def __init__(self, run_fn, workers: int = 2, queue_max: int = 100):
        self.run_fn = run_fn
        self.n = workers
        self.q: queue.Queue[str | None] = queue.Queue(maxsize=queue_max)
        self.threads: list[threading.Thread] = []
        self.started = False

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        for i in range(self.n):
            t = threading.Thread(target=self._loop, name=f"cg-worker-{i}", daemon=True)
            t.start()
            self.threads.append(t)

    def submit(self, job_id: str) -> None:
        try:
            self.q.put_nowait(job_id)
        except queue.Full:
            raise QueueFull() from None

    def _loop(self) -> None:
        while True:
            job_id = self.q.get()
            try:
                if job_id is None:
                    return
                self.run_fn(job_id)
            except Exception:  # noqa: BLE001 - pipeline already records failures; never kill the worker
                log.exception("worker crashed on job %s", job_id)
            finally:
                self.q.task_done()

    def stop(self, timeout: float = 5.0) -> None:
        if not self.started:
            return
        for _ in self.threads:
            try:
                self.q.put(None, timeout=timeout)
            except queue.Full:
                break
        for t in self.threads:
            t.join(timeout=timeout)
        self.threads.clear()
        self.started = False
