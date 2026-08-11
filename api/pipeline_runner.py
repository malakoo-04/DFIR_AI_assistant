"""
api/pipeline_runner.py

Thin in-process job layer around the EXISTING DFIR-AI pipeline logic.

Existing production pipelines:
    scripts/run_final_report.py   -> generate_final_report()
    scripts/run_ioc_extraction.py -> generate_ioc_report()

Independent analysis:
    scripts/run_hayabusa.py -> generate_hayabusa_report()

This module does not reimplement DFIR logic. It only:
- starts the existing callable functions in background threads;
- captures their real stdout lines for the GUI;
- tracks job status/results/errors;
- exposes a small seam for FastAPI.

Hayabusa is deliberately independent from the DFIR report and IOC pipeline.
"""

from __future__ import annotations

import re
import sys
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# ------------------------------------------------------------------
# Project imports
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import run_final_report  # noqa: E402
from scripts import run_ioc_extraction  # noqa: E402
from scripts import run_hayabusa  # noqa: E402


# ------------------------------------------------------------------
# Job model
# ------------------------------------------------------------------
class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class JobType(str, Enum):
    REPORT = "report"
    IOC = "ioc"
    HAYABUSA = "hayabusa"


@dataclass
class Job:
    job_id: str
    job_type: JobType
    status: JobStatus = JobStatus.QUEUED
    result: Optional[dict] = None
    error: Optional[str] = None

    # Structured progress emitted by production scripts.
    phase: Optional[str] = None
    stats: dict = field(default_factory=dict)

    # Real console lines captured from the worker thread.
    logs: list[str] = field(default_factory=list)

    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()

_EXECUTOR = ThreadPoolExecutor(
    max_workers=2,
    thread_name_prefix="dfir-job",
)

ALLOWED_OUTPUT_ROOTS = (PROJECT_ROOT / "output",)


# ------------------------------------------------------------------
# Thread-local stdout routing
# ------------------------------------------------------------------
_LOG_CONTEXT = threading.local()
_REAL_STDOUT = sys.stdout


class _JobLogTee:
    """Write to the real stdout and capture complete lines for the active job."""

    def __init__(self, real_stdout):
        self._real_stdout = real_stdout

    def write(self, data):
        self._real_stdout.write(data)
        self._real_stdout.flush()

        job = getattr(_LOG_CONTEXT, "job", None)

        if job is None or not data:
            return len(data)

        buffer = getattr(_LOG_CONTEXT, "buffer", "") + data
        parts = buffer.split("\n")
        _LOG_CONTEXT.buffer = parts.pop()

        for line in parts:
            _ingest_log_line(job, line.rstrip("\r"))

        return len(data)

    def flush(self):
        self._real_stdout.flush()

    def __getattr__(self, name):
        return getattr(self._real_stdout, name)


if not isinstance(sys.stdout, _JobLogTee):
    sys.stdout = _JobLogTee(_REAL_STDOUT)


def _bind_job_logging(job: Job) -> None:
    _LOG_CONTEXT.job = job
    _LOG_CONTEXT.buffer = ""


def _unbind_job_logging(job: Job) -> None:
    if getattr(_LOG_CONTEXT, "job", None) is job:
        buffer = getattr(_LOG_CONTEXT, "buffer", "")

        if buffer:
            _ingest_log_line(
                job,
                buffer.rstrip("\r"),
            )

        _LOG_CONTEXT.buffer = ""
        _LOG_CONTEXT.job = None


# ------------------------------------------------------------------
# Structured progress parsing
# ------------------------------------------------------------------
_PHASE_RE = re.compile(
    r"^\[PHASE\]\s*(.+?)\s*$"
)

_STAT_RE = re.compile(
    r"^\[STAT\]\s*([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$"
)

_INCIDENTS_RE = re.compile(
    r"^Incidents generated:\s*(\d+)\s*$"
)


# ------------------------------------------------------------------
# Hayabusa native-output parsing
# ------------------------------------------------------------------
_HAYA_FOUND_RE = re.compile(
    r"^Hayabusa:\s*found\s+(\d+)\s+EVTX files\.",
    re.IGNORECASE,
)

_HAYA_TOTAL_RE = re.compile(
    r"^Total event log files:\s*(\d+)\s*$",
    re.IGNORECASE,
)

_HAYA_LOADED_RE = re.compile(
    r"^Evtx files loaded after channel filter:\s*(\d+)\s*$",
    re.IGNORECASE,
)

_HAYA_SCAN_RE = re.compile(
    r"^\[.*\]\s*\d+\s*/\s*\d+\s+.*100%",
)

_HAYA_OUTPUT_RE = re.compile(
    r"^Saved file:\s*(.+)$",
    re.IGNORECASE,
)


def _ingest_hayabusa_line(
    job: Job,
    line: str,
) -> None:
    """
    Convert Hayabusa's real console output into structured job state.

    This does NOT invent values.

    Examples handled:

        Total event log files: 115
        Evtx files loaded after channel filter: 24
        Scanning in progress. Please wait.
        Scanning finished. Please wait while the results are being saved.
        Saved file: hayabusa_results.csv
    """

    # --------------------------------------------------------------
    # EVTX discovery
    # --------------------------------------------------------------
    match = _HAYA_FOUND_RE.match(line)

    if match:
        job.phase = "DISCOVERY"
        job.stats["evtx_files_found"] = int(
            match.group(1)
        )
        return

    match = _HAYA_TOTAL_RE.match(line)

    if match:
        job.phase = "DISCOVERY"
        job.stats["evtx_files_found"] = int(
            match.group(1)
        )
        return

    # --------------------------------------------------------------
    # Hayabusa initialization / rules loading
    # --------------------------------------------------------------
    if "Loading detection rules." in line:
        job.phase = "HAYABUSA_SCAN"
        return

    if "Creating the channel filter." in line:
        job.phase = "HAYABUSA_SCAN"
        return

    # --------------------------------------------------------------
    # Real EVTX files loaded after channel filtering
    # --------------------------------------------------------------
    match = _HAYA_LOADED_RE.match(line)

    if match:
        job.phase = "HAYABUSA_SCAN"
        job.stats["evtx_files_loaded"] = int(
            match.group(1)
        )
        return

    # --------------------------------------------------------------
    # Actual scanning
    # --------------------------------------------------------------
    if "Scanning in progress." in line:
        job.phase = "SCANNING"
        return

    # Hayabusa's progress-bar line can also indicate active scanning.
    if _HAYA_SCAN_RE.match(line):
        job.phase = "SCANNING"
        return

    # --------------------------------------------------------------
    # Result export
    # --------------------------------------------------------------
    if "Scanning finished." in line:
        job.phase = "SAVING_RESULTS"
        return

    match = _HAYA_OUTPUT_RE.match(line)

    if match:
        job.phase = "SAVING_RESULTS"
        return


def _ingest_log_line(
    job: Job,
    line: str,
) -> None:

    if not line:
        return

    phase = None
    stat_key = None
    stat_value = None

    # --------------------------------------------------------------
    # Existing generic DFIR / IOC markers
    # --------------------------------------------------------------
    phase_match = _PHASE_RE.match(line)

    if phase_match:
        phase = phase_match.group(1).strip()

    stat_match = _STAT_RE.match(line)

    if stat_match:
        stat_key = stat_match.group(1)

        raw = stat_match.group(2).strip()

        try:
            stat_value = int(raw)

        except ValueError:
            try:
                stat_value = float(raw)

            except ValueError:
                stat_value = raw

    incidents_match = _INCIDENTS_RE.match(line)

    if incidents_match:
        stat_key = "incidents_generated"
        stat_value = int(
            incidents_match.group(1)
        )

    # --------------------------------------------------------------
    # Store the actual console line
    # --------------------------------------------------------------
    with job.lock:

        job.logs.append(line)

        if phase is not None:
            job.phase = phase

        if stat_key is not None:
            job.stats[stat_key] = stat_value

        # ----------------------------------------------------------
        # Hayabusa-specific native output
        # ----------------------------------------------------------
        if job.job_type == JobType.HAYABUSA:
            _ingest_hayabusa_line(
                job,
                line,
            )


def job_to_logs_dict(
    job: Job,
    since: int = 0,
) -> dict:

    try:
        offset = max(
            0,
            int(since),
        )

    except (TypeError, ValueError):
        offset = 0

    with job.lock:

        total = len(job.logs)
        lines = job.logs[offset:]

        return {
            "job_id": job.job_id,
            "lines": [
                {
                    "index": offset + i,
                    "text": line,
                }
                for i, line in enumerate(lines)
            ],
            "next_offset": total,
        }


# ------------------------------------------------------------------
# Job registry
# ------------------------------------------------------------------
def _new_job(job_type: JobType) -> Job:

    job = Job(
        job_id=uuid.uuid4().hex,
        job_type=job_type,
    )

    with _JOBS_LOCK:
        _JOBS[job.job_id] = job

    return job


def get_job(
    job_id: str,
) -> Optional[Job]:

    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def _set_failed(
    job: Job,
    exc: BaseException,
) -> None:

    with job.lock:

        if isinstance(exc, SystemExit):
            job.error = (
                f"Pipeline exited with code {exc.code}"
            )

        else:
            job.error = traceback.format_exc()

        job.status = JobStatus.FAILED


# ------------------------------------------------------------------
# Workers
# ------------------------------------------------------------------
def _run_report(job: Job) -> None:

    _bind_job_logging(job)

    with job.lock:
        job.status = JobStatus.RUNNING

    try:

        result = (
            run_final_report
            .generate_final_report()
        )

        with job.lock:
            job.result = result or {}
            job.status = JobStatus.COMPLETED

    except BaseException as exc:
        _set_failed(
            job,
            exc,
        )

    finally:
        _unbind_job_logging(job)


def _run_ioc(job: Job) -> None:

    _bind_job_logging(job)

    with job.lock:
        job.status = JobStatus.RUNNING

    try:

        result = (
            run_ioc_extraction
            .generate_ioc_report()
        )

        with job.lock:
            job.result = result or {}
            job.status = JobStatus.COMPLETED

    except BaseException as exc:
        _set_failed(
            job,
            exc,
        )

    finally:
        _unbind_job_logging(job)


def _run_hayabusa(job: Job) -> None:

    _bind_job_logging(job)

    with job.lock:
        job.status = JobStatus.RUNNING

        # This is the real first phase of the wrapper:
        # discovering the EVTX files before launching Hayabusa.
        job.phase = "DISCOVERY"

    try:

        result = (
            run_hayabusa
            .generate_hayabusa_report(
                log_callback=print,
            )
        )

        if not result.success:

            with job.lock:

                job.error = (
                    result.error
                    or (
                        "Hayabusa exited with code "
                        f"{result.exit_code}"
                    )
                )

                job.status = JobStatus.FAILED

            return

        with job.lock:

            job.phase = "COMPLETED"

            job.result = {
                "job_id": job.job_id,
                "status": JobStatus.COMPLETED.value,
                "hayabusa_report": str(
                    result.output_path
                ),
                "hayabusa_html_report": str(
                    result.html_output_path
                ),
                "evtx_files_found":
                    result.evtx_files_found,
                "evtx_files_loaded":
                    job.stats.get(
                        "evtx_files_loaded"
                    ),
                "exit_code":
                    result.exit_code,
            }

            # Keep the independently returned count authoritative.
            job.stats["evtx_files_found"] = (
                result.evtx_files_found
            )

            job.status = JobStatus.COMPLETED

    except BaseException as exc:

        _set_failed(
            job,
            exc,
        )

    finally:
        _unbind_job_logging(job)


# ------------------------------------------------------------------
# Submission
# ------------------------------------------------------------------
def submit_report_job() -> Job:

    job = _new_job(
        JobType.REPORT
    )

    _EXECUTOR.submit(
        _run_report,
        job,
    )

    return job


def submit_ioc_job() -> Job:

    job = _new_job(
        JobType.IOC
    )

    _EXECUTOR.submit(
        _run_ioc,
        job,
    )

    return job


def submit_hayabusa_job() -> Job:

    job = _new_job(
        JobType.HAYABUSA
    )

    _EXECUTOR.submit(
        _run_hayabusa,
        job,
    )

    return job


# ------------------------------------------------------------------
# API serialization / safe file serving
# ------------------------------------------------------------------
def job_to_status_dict(
    job: Job,
) -> dict:

    with job.lock:

        return {
            "job_id":
                job.job_id,

            "status":
                job.status.value,

            "job_type":
                job.job_type.value,

            "phase":
                job.phase,

            "stats":
                dict(job.stats),
        }


def job_to_result_dict(
    job: Job,
) -> dict:

    with job.lock:

        if job.status != JobStatus.COMPLETED:

            return {
                "job_id":
                    job.job_id,

                "status":
                    job.status.value,

                "result":
                    None,
            }

        return job.result or {}


def resolve_output_file(
    job: Job,
    artifact_key: str,
) -> Optional[Path]:
    """
    Resolve a generated output path while preventing access outside
    PROJECT_ROOT/output.
    """

    with job.lock:

        if (
            job.status
            != JobStatus.COMPLETED
            or not job.result
        ):
            return None

        value = job.result.get(
            artifact_key
        )

    if not value:
        return None

    candidate = Path(value)

    if not candidate.is_absolute():
        candidate = (
            PROJECT_ROOT / candidate
        )

    candidate = candidate.resolve()

    if not any(
        candidate == root.resolve()
        or root.resolve() in candidate.parents
        for root in ALLOWED_OUTPUT_ROOTS
    ):
        return None

    if not candidate.is_file():
        return None

    return candidate