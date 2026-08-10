"""
api/pipeline_runner.py

Thin, in-process job layer around the EXISTING pipeline logic.

This module does NOT reimplement any DFIR logic. It imports the two
production entry points and calls their callable pipeline functions
directly on a background thread:

    scripts/run_final_report.py      -> generate_final_report()
    scripts/run_ioc_extraction.py    -> generate_ioc_report()

Those two scripts still keep a CLI-oriented main() for
`python scripts/run_final_report.py`, but the actual pipeline body now
lives in generate_final_report() / generate_ioc_report(), which is
what this layer calls. Production code must never import from the
tests/ package -- these are production entry points under scripts/.

Why threads instead of subprocess:
    - No new Python process / interpreter startup cost.
    - Exceptions propagate as real Python exceptions we can catch and
      store, instead of having to parse stderr/return codes.
    - Calling a plain function directly is simpler and cleaner than
      calling main() and re-deriving results from module constants.

Job state lives in memory (a plain dict guarded by a lock). That is
sufficient for a single-process FastAPI deployment. If the API is ever
scaled to multiple worker processes, this in-memory store should be
swapped for something shared (e.g. Redis) -- the public functions below
(`get_job`, `submit_report_job`, `submit_ioc_job`) are the seam where
that swap would happen, so callers do not need to change.
"""

from __future__ import annotations

import io
import sys
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

# ------------------------------------------------------------------
# Make sure the project root (the directory that contains `modules/`,
# `tests/`, `scripts/`, etc.) is importable regardless of the working
# directory uvicorn was launched from. scripts/run_final_report.py and
# scripts/run_ioc_extraction.py both do `from modules...` imports that
# assume the project root is on sys.path.
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Reuse the existing pipeline functions as-is. Nothing below imports
# subprocess, and nothing below imports from tests/.
from scripts import run_final_report  # noqa: E402
from scripts import run_ioc_extraction  # noqa: E402


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobType(str, Enum):
    REPORT = "report"
    IOC = "ioc"


@dataclass
class Job:
    job_id: str
    job_type: JobType
    status: JobStatus = JobStatus.QUEUED
    result: Optional[dict] = None
    error: Optional[str] = None
    logs: list[str] = field(default_factory=list, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def log(self, line: str) -> None:
        """Append one already-formatted log line to this job's log buffer."""
        with self.lock:
            self.logs.append(line)


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()

# ------------------------------------------------------------------
# Live log capture.
#
# The pipeline (modules/, scripts/run_final_report.py,
# scripts/run_ioc_extraction.py) reports progress exclusively via
# print(), e.g. "Incidents generated: 815", "Candidate IOCs: 1779",
# "Waiting 65 seconds for Gemini quota reset...". Nothing in that
# code is touched: instead, sys.stdout is replaced *once*, at import
# time, with a small tee that still writes through to the real
# stdout (so `uvicorn` console output / logs are unaffected) and
# additionally routes each completed line into whichever Job is
# currently "active" on the calling thread.
#
# Routing is done via threading.local() rather than a global,
# because the executor may run two jobs concurrently (different
# threads) and each must only see its own output.
# ------------------------------------------------------------------

_LOG_CONTEXT = threading.local()


class _JobLogTee(io.TextIOBase):
    """Writes through to the wrapped stream and mirrors complete
    lines to the Job bound to the current thread (if any)."""

    def __init__(self, wrapped):
        self._wrapped = wrapped

    def write(self, s: str) -> int:
        self._wrapped.write(s)

        job = getattr(_LOG_CONTEXT, "job", None)
        if job is not None and s:
            buf = getattr(_LOG_CONTEXT, "buf", "") + s
            *complete, remainder = buf.split("\n")
            for line in complete:
                if line.strip():
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    job.log(f"[{ts}] {line}")
            _LOG_CONTEXT.buf = remainder
        return len(s)

    def flush(self) -> None:
        self._wrapped.flush()


# Install once. Safe to import this module multiple times (FastAPI /
# uvicorn --reload notwithstanding) because we only wrap whatever
# sys.stdout currently is, once, on first import.
if not isinstance(sys.stdout, _JobLogTee):
    sys.stdout = _JobLogTee(sys.stdout)


def _bind_job_logging(job: Job) -> None:
    _LOG_CONTEXT.job = job
    _LOG_CONTEXT.buf = ""


def _unbind_job_logging(job: Job) -> None:
    # Flush whatever partial line is left (e.g. a print without a
    # trailing newline, or the process being between prints).
    remainder = getattr(_LOG_CONTEXT, "buf", "")
    if remainder.strip():
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        job.log(f"[{ts}] {remainder}")
    _LOG_CONTEXT.job = None
    _LOG_CONTEXT.buf = ""

# Small pool: the underlying pipeline is itself heavy (parsing + LLM
# calls), so we cap concurrency rather than spawning unbounded threads
# per request.
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dfir-job")

# Output roots the file-serving endpoint is allowed to read from.
# Every path returned by generate_final_report() / generate_ioc_report()
# lives under one of these -- used to reject anything unexpected before
# it's ever handed to a FileResponse.
ALLOWED_OUTPUT_ROOTS = (PROJECT_ROOT / "output",)


def _new_job(job_type: JobType) -> Job:
    job_id = uuid.uuid4().hex
    job = Job(job_id=job_id, job_type=job_type, status=JobStatus.QUEUED)
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    return job


def get_job(job_id: str) -> Optional[Job]:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def _run_report(job: Job) -> None:
    with job.lock:
        job.status = JobStatus.RUNNING
    _bind_job_logging(job)
    try:
        # Reuse the existing full pipeline function exactly as-is.
        result = run_final_report.generate_final_report()
        with job.lock:
            # result is None when the pipeline ran successfully but
            # produced no incidents (see generate_final_report()).
            job.result = result or {}
            job.status = JobStatus.COMPLETED
    except BaseException as exc:  # noqa: BLE001 - see module note below
        # Catch BaseException, not just Exception: run_final_report
        # still calls sys.exit(1) on failure (SystemExit is a
        # BaseException, not an Exception), and this thread must
        # never let *anything* -- SystemExit, KeyboardInterrupt,
        # GeneratorExit, whatever -- escape unhandled and leave the
        # job stuck at RUNNING forever.
        with job.lock:
            if isinstance(exc, SystemExit):
                job.error = f"Pipeline exited with code {exc.code}"
            else:
                job.error = traceback.format_exc()
            job.status = JobStatus.FAILED
    finally:
        _unbind_job_logging(job)


def _run_ioc(job: Job) -> None:
    with job.lock:
        job.status = JobStatus.RUNNING
    _bind_job_logging(job)
    try:
        # Reuse the existing IOC-only pipeline function exactly as-is.
        result = run_ioc_extraction.generate_ioc_report()
        with job.lock:
            job.result = result or {}
            job.status = JobStatus.COMPLETED
    except BaseException as exc:  # noqa: BLE001 - see _run_report for rationale
        with job.lock:
            if isinstance(exc, SystemExit):
                job.error = f"Pipeline exited with code {exc.code}"
            else:
                job.error = traceback.format_exc()
            job.status = JobStatus.FAILED
    finally:
        _unbind_job_logging(job)


def submit_report_job() -> Job:
    """Kick off scripts/run_final_report.py::generate_final_report() in the background."""
    job = _new_job(JobType.REPORT)
    _EXECUTOR.submit(_run_report, job)
    return job


def submit_ioc_job() -> Job:
    """Kick off scripts/run_ioc_extraction.py::generate_ioc_report() in the background."""
    job = _new_job(JobType.IOC)
    _EXECUTOR.submit(_run_ioc, job)
    return job


def job_to_status_dict(job: Job) -> dict:
    with job.lock:
        return {"job_id": job.job_id, "status": job.status.value}


def job_to_logs_dict(job: Job, since: int = 0) -> dict:
    """
    Return log lines appended after index `since`, plus the offset the
    caller should pass as `since` on its next poll. `since` <= 0 (or
    beyond the end, e.g. after a job was cleared) is clamped safely.
    """
    with job.lock:
        total = len(job.logs)
        start = since if 0 <= since <= total else 0
        new_lines = job.logs[start:]
        return {
            "job_id": job.job_id,
            "status": job.status.value,
            "logs": new_lines,
            "next_offset": total,
        }


def job_to_result_dict(job: Job) -> dict:
    with job.lock:
        if job.status != JobStatus.COMPLETED:
            return {"job_id": job.job_id, "status": job.status.value, "result": None}
        return job.result or {}


def resolve_output_file(job: Job, artifact_key: str) -> Optional[Path]:
    """
    Resolve `job.result[artifact_key]` to an absolute path, but only if
    it's a real file living under one of ALLOWED_OUTPUT_ROOTS. Returns
    None if the job isn't completed, the key doesn't exist, or the
    path fails validation -- callers turn that into a 404.
    """
    with job.lock:
        if job.status != JobStatus.COMPLETED or not job.result:
            return None
        rel_or_abs = job.result.get(artifact_key)

    if not rel_or_abs:
        return None

    candidate = (PROJECT_ROOT / rel_or_abs).resolve()

    if not any(
        candidate == root.resolve() or root.resolve() in candidate.parents
        for root in ALLOWED_OUTPUT_ROOTS
    ):
        return None

    if not candidate.is_file():
        return None

    return candidate
