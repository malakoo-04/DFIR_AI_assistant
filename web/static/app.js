/* ============================================================
   app.js — DFIR-AI frontend
   No frameworks, no iframes, no History API, no location changes.
   Everything is one document; navigation = show/hide + class toggles.

   This file does two things only:
     1. Declares `state` — shared across router.js/login.js/new_case.js/
        progress.js/results.js (all plain globals, loaded before this
        file so its functions exist by the time state is used).
     2. Waits for DOMContentLoaded and calls each module's init
        function. Using DOMContentLoaded explicitly (rather than
        relying on `defer` alone) makes startup robust even if a
        script tag's defer behavior is ever affected by how the page
        is loaded (e.g. certain embedding contexts).

   Load order in index.html: router.js, login.js, new_case.js,
   progress.js, results.js, api.js, app.js (this file, last).
   api.js is loaded but not yet called anywhere — see its own
   header comment.
   ============================================================ */

const state = {
  fileName: null,
  fileSize: null,
  runType: null,      // 'dfir' | 'ioc' | 'haya'
  invName: '',
  startTime: null,
  timer: null,
  elapsedTimer: null,
};

document.addEventListener('DOMContentLoaded', function init() {
  Router.bindNavTriggers();
  initLogin();
  initDropzone();
  initResults();
});
