"""
Lightweight in-memory job tracking for a single-user local tool.

No database, no Redis, no Celery — just a thread-safe dict and a bounded
ThreadPoolExecutor. Jobs are lost on restart, which is the right trade-off
for a local analyst tool (re-running an analysis is cheap and files stay
on disk under UPLOAD_DIR until you clean them up).
"""
import threading
import traceback
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from config import MAX_CONCURRENT_JOBS

VALID_STATUSES = {"queued", "running", "done", "error", "cancelled"}


class JobCancelled(Exception):
    """Raised inside a pipeline (via the is_cancelled() check) to unwind
    cleanly when a user cancels a running job."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Job:
    id: str
    filenames: List[str]
    owner_id: Optional[int] = None  # which user submitted this job
    status: str = "queued"
    stage: str = "Queued"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    cancel_requested: bool = False

    def to_summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "filenames": self.filenames,
            "status": self.status,
            "stage": self.stage,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "cancel_requested": self.cancel_requested,
        }

    def to_full(self) -> Dict[str, Any]:
        d = self.to_summary()
        d["error"] = self.error
        d["result"] = self.result
        return d


class JobManager:
    def __init__(self, max_workers: int = MAX_CONCURRENT_JOBS):
        self._jobs: Dict[str, Job] = {}
        self._futures: Dict[str, Future] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dfir-job")

    def create_job(self, filenames: List[str], owner_id: Optional[int] = None) -> Job:
        job_id = str(uuid.uuid4())
        job = Job(id=job_id, filenames=filenames, owner_id=owner_id)
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self, owner_id: Optional[int] = None) -> List[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if owner_id is not None:
            jobs = [j for j in jobs if j.owner_id == owner_id]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def _set(self, job_id: str, **kwargs) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for k, v in kwargs.items():
                setattr(job, k, v)
            job.updated_at = _now()

    def update_stage(self, job_id: str, stage: str) -> None:
        self._set(job_id, stage=stage, status="running")

    def is_cancel_requested(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            return bool(job and job.cancel_requested)

    def cancel(self, job_id: str) -> bool:
        """
        Best-effort cancel:
          - If the job hasn't started running yet (still queued behind
            MAX_CONCURRENT_JOBS), the underlying Future can be cancelled
            outright -- it never runs at all.
          - If it's already running, this sets a cooperative flag. The
            pipeline checks it between stages (see pipeline_adapter.py) and
            raises JobCancelled to unwind cleanly. It will NOT interrupt a
            stage already in flight (e.g. a live Ollama HTTP call) -- it
            stops at the next checkpoint after that.
        Returns False if the job doesn't exist or already reached a
        terminal state.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in ("done", "error", "cancelled"):
                return False

            job.cancel_requested = True
            job.updated_at = _now()

            future = self._futures.get(job_id)
            if future is not None and future.cancel():
                # Wasn't running yet -- _run() body never executes at all,
                # so set the terminal state here since nothing else will.
                job.status = "cancelled"
                job.stage = "Cancelled by user"

        return True

    def submit(self, job_id: str, target: Callable[..., Dict[str, Any]], *args, **kwargs) -> None:
        """Queue `target(job_id, *args, is_cancelled=<callable>, **kwargs)` on
        the background worker pool. `target` should check `is_cancelled()`
        between stages and raise JobCancelled to stop early."""

        def _run():
            self._set(job_id, status="running", stage="Starting analysis")
            try:
                result = target(
                    job_id, *args,
                    is_cancelled=lambda: self.is_cancel_requested(job_id),
                    **kwargs,
                )
                self._set(job_id, status="done", stage="Complete", result=result)
            except JobCancelled:
                self._set(job_id, status="cancelled", stage="Cancelled by user")
            except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
                self._set(
                    job_id,
                    status="error",
                    stage="Failed",
                    error=f"{exc}\n\n{traceback.format_exc()}",
                )

        future = self._executor.submit(_run)
        with self._lock:
            self._futures[job_id] = future


job_manager = JobManager()
