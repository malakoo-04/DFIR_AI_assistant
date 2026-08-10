"""
api/main.py

FastAPI backend that wraps the EXISTING DFIR pipeline logic.

This file contains no pipeline logic of its own. It only:
    1. Exposes HTTP endpoints.
    2. Delegates to api/pipeline_runner.py, which imports and calls
       scripts/run_final_report.py::generate_final_report() and
       scripts/run_ioc_extraction.py::generate_ioc_report() directly
       (production entry points under scripts/, never tests/).

Package name: `api/` (not `backend/`) because `modules/` already *is*
the application backend (discovery, parsers, correlation, agents...).
This package's only job is to expose that backend over HTTP.

Run (from the project root):
    uvicorn api.main:app --reload

Endpoints:
    POST /api/report                       -> run the full DFIR pipeline
    POST /api/ioc                          -> run the IOC-only pipeline
    POST /api/hayabusa                      -> architecture placeholder, not implemented yet
    GET  /api/status/{job_id}                -> queued | running | completed | failed
    GET  /api/logs/{job_id}?since=N          -> live console output (real print() lines from the pipeline)
    GET  /api/result/{job_id}                -> output file paths once completed
    GET  /api/file/{job_id}/{artifact_key}    -> download/open a generated file (e.g. final_report, ioc_report)
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from api.pipeline_runner import (
    JobStatus,
    get_job,
    job_to_logs_dict,
    job_to_result_dict,
    job_to_status_dict,
    resolve_output_file,
    submit_ioc_job,
    submit_report_job,
)

app = FastAPI(title="DFIR AI Assistant API")

# Permissive for now (GUI may be served from a different origin during
# development, e.g. a static file server / live-reload tool). Tighten
# this once the deployment topology (same-origin vs separate host) is
# decided.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/report")
def start_report_job():
    """Kick off the full DFIR pipeline. Async."""
    job = submit_report_job()
    return job_to_status_dict(job)


@app.post("/api/ioc")
def start_ioc_job():
    """Kick off the IOC-only pipeline. Async."""
    job = submit_ioc_job()
    return job_to_status_dict(job)


@app.post("/api/hayabusa")
def start_hayabusa_job():
    """
    Placeholder only. Hayabusa is a separate, independent module
    (Uploaded KAPE ZIP -> DFIR Pipeline / Hayabusa in parallel) and is
    not wired up yet. No job is created here.
    """
    return {"status": "not_implemented"}


@app.get("/api/status/{job_id}")
def get_status(job_id: str):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    return job_to_status_dict(job)


@app.get("/api/logs/{job_id}")
def get_logs(job_id: str, since: int = 0):
    """
    Live backend console output for a job — the real print() lines
    emitted by the pipeline (Discovery, Parsers, Timeline, Correlation,
    the LLM agents, e.g. "Incidents generated: 815",
    "Waiting 65 seconds for Gemini quota reset..."), not simulated text.

    `since` is the `next_offset` returned by the previous call (0 on
    the first call). Only the lines appended after that point are
    returned, so the frontend can poll this cheaply once a second.
    """
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    return job_to_logs_dict(job, since=since)


@app.get("/api/result/{job_id}")
def get_result(job_id: str):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    if job.status == JobStatus.FAILED:
        raise HTTPException(status_code=500, detail=job.error or "Job failed")
    if job.status != JobStatus.COMPLETED:
        raise HTTPException(
            status_code=409,
            detail=f"Job is not completed yet (status={job.status.value})",
        )
    return job_to_result_dict(job)


@app.get("/api/file/{job_id}/{artifact_key}")
def get_file(job_id: str, artifact_key: str):
    """
    Serve one generated output file, e.g.:
        GET /api/file/<job_id>/final_report
        GET /api/file/<job_id>/ioc_report

    `artifact_key` is one of the keys returned by GET /api/result/{job_id}
    (e.g. "final_report", "investigation_report", "ioc_report"). Used by
    the Results page for both "Open" (opened in a new tab) and
    "Download" (same URL, browser saves it).
    """
    job = get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job_id")

    path = resolve_output_file(job, artifact_key)
    if path is None:
        raise HTTPException(
            status_code=404,
            detail=f"No file found for artifact '{artifact_key}' on job {job_id}",
        )

    return FileResponse(path, filename=path.name)
