/* ============================================================
   api.js — DFIR-AI frontend
   Thin fetch() wrappers around the future FastAPI backend.

   NOT CALLED ANYWHERE YET. This file is pure preparation for the
   next increment, when launchPipeline() (new_case.js) and
   runSimulatedPipeline() (progress.js) get replaced with real
   POST /api/report | /api/ioc | /api/hayabusa and
   GET /api/status/{job_id} / /api/result/{job_id} calls. Nothing
   in this pass wires these in — the placeholder simulation is
   untouched.
   ------------------------------------------------------------ */

async function apiGet(path) {
  const res = await fetch(path, { method: 'GET' });
  if (!res.ok) {
    throw new Error('GET ' + path + ' failed: ' + res.status);
  }
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    throw new Error('POST ' + path + ' failed: ' + res.status);
  }
  return res.json();
}
