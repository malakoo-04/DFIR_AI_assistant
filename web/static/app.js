/* ============================================================
   app.js — DFIR-AI frontend

   No frameworks, no iframes, no History API, no location changes.
   Everything is one document; navigation = show/hide + class toggles.

   This file does two things only:

   1. Declares `state` — shared across router.js/login.js/
      new_case.js/progress.js/results.js.

   2. Waits for DOMContentLoaded and calls each module's init
      function.

   Load order in index.html:
   router.js
   login.js
   new_case.js
   progress.js
   results.js
   api.js
   app.js
   ============================================================ */

const state = {

  fileName: null,

  fileSize: null,

  runType: null,
  // 'dfir' | 'ioc' | 'haya'

  invName: '',

  startTime: null,

  timer: null,

  elapsedTimer: null,

  /*
   * Incremented every time a new pipeline is launched.
   *
   * This prevents stale polling from an older job from
   * updating the UI of a newer job.
   */
  runGen: 0,

  /*
   * Real structured statistics returned by:
   *
   * GET /api/status/{job_id}
   *
   * progress.js updates this object from the backend.
   *
   * Example for Hayabusa:
   *
   * {
   *   evtx_files_found: 115,
   *   evtx_files_loaded: 24,
   *   detections: 15341,
   *   critical: 0,
   *   channels: 14
   * }
   *
   * IMPORTANT:
   * No numbers are initialized here.
   * The backend is the source of truth.
   */
  jobStats: {},

  /*
   * Real generated artifact paths returned by the backend.
   *
   * Example:
   *
   * {
   *   final_report: "...",
   *   ioc_report: "...",
   *   hayabusa_report: "..."
   * }
   */
  resultPaths: {},

  /*
   * Current backend job ID.
   */
  jobId: null

};


/* ============================================================
   Application startup
   ============================================================ */

document.addEventListener(
  'DOMContentLoaded',
  function init() {

    Router.bindNavTriggers();

    initLogin();

    initDropzone();

    initResults();

  }
);