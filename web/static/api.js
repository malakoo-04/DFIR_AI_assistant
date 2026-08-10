/* ============================================================
   api.js — DFIR-AI frontend
   Thin fetch() wrappers around the FastAPI backend (api/main.py).

   Used by progress.js's runRealPipeline() to call
   POST /api/report | /api/ioc | /api/hayabusa and
   GET /api/status/{job_id} | /api/logs/{job_id} | /api/result/{job_id},
   and by results.js's realDownload()/preview handling to build
   GET /api/file/{job_id}/{artifact_key} URLs.
   ------------------------------------------------------------ */

const API_BASE = "http://127.0.0.1:8000";
async function apiGet(path) {
  const res = await fetch(API_BASE + path, { method: 'GET' });
  if (!res.ok) {
    throw new Error('GET ' + path + ' failed: ' + res.status);
  }
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(API_BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    throw new Error('POST ' + path + ' failed: ' + res.status);
  }
  return res.json();
}
