/* ============================================================
   new_case.js — DFIR-AI frontend
   "New investigation" page: file drop/browse, form validation,
   and launchPipeline() — the single entry point that starts a run.

   launchPipeline() sets up the progress-page UI and hands off to
   runRealPipeline(runType, pipeline) (progress.js), which POSTs
   /api/report or /api/ioc, polls GET /api/status/{job_id}, and on
   completion stores the real result paths on `state` for results.js.

   Uses the shared `state` object declared in app.js.
   ------------------------------------------------------------ */

function initDropzone() {
  const dropzone = $('dropzone');
  if (!dropzone) return;

  dropzone.addEventListener('click', function () {
    const input = $('fileInput');
    if (input) input.click();
  });

  ['dragenter', 'dragover'].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(function (evt) {
    dropzone.addEventListener(evt, function (e) {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', function (e) {
    const files = e.dataTransfer.files;
    if (files && files.length) handleFileSelect(files);
  });

  const fileInput = $('fileInput');
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      handleFileSelect(this.files);
    });
  }

  const clearBtn = $('btnClearFile');
  if (clearBtn) clearBtn.addEventListener('click', clearFile);

  const nameField = $('invName');
  if (nameField) nameField.addEventListener('input', validateForm);

  document.querySelectorAll('[data-run]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      launchPipeline(btn.dataset.run);
    });
  });
}

function handleFileSelect(files) {
  if (!files || !files.length) return;
  const f = files[0];
  state.fileName = f.name;
  state.fileSize = (f.size / (1024 * 1024)).toFixed(1);

  $('filePickedName').textContent = f.name;
  $('filePickedSub').textContent =
    (state.fileSize > 0 ? state.fileSize + ' MB · ' : '') + 'Ready for analysis';
  $('filePicked').style.display = 'flex';
  $('dropzone').style.display = 'none';

  validateForm();
}

function clearFile(e) {
  if (e) e.stopPropagation();
  state.fileName = null;
  $('fileInput').value = '';
  $('filePicked').style.display = 'none';
  $('dropzone').style.display = 'block';
  validateForm();
}

function validateForm() {
  const nameField = $('invName');
  const name = nameField ? nameField.value.trim() : '';
  const ready = !!name && !!state.fileName;

  ['btnDfir', 'btnIoc', 'btnHaya'].forEach(function (id) {
    const btn = $(id);
    if (btn) btn.disabled = !ready;
  });
}

function launchPipeline(runType) {
  // Prevent duplicate submissions: ignore extra clicks while a run
  // is already in flight for this generation.
  if (state.runInFlight) return;
  state.runInFlight = true;
  ['btnDfir', 'btnIoc', 'btnHaya'].forEach(function (id) {
    const btn = $(id);
    if (btn) btn.disabled = true;
  });

  state.runGen++;
  state.runType = runType;
  state.invName = ($('invName').value.trim()) || 'Untitled investigation';
  const pipeline = PIPELINES[runType];

  $('progTitle').textContent = state.invName;
  $('progRunLabel').textContent = pipeline.label;
  $('progBadge').className = 'prog-status-badge running';
  $('progBadgeText').textContent = 'Running';
  $('progFill').style.width = '0%';
  $('progPercent').textContent = '0%';
  $('progStageLabel').textContent = 'Initializing…';
  $('progViewResults').style.display = 'none';

  const cancelBtn = $('progCancelBtn');
  cancelBtn.textContent = 'Back to setup';
  // See router.js: retargeting data-nav is enough, the click
  // listener bound at DOMContentLoaded re-reads it every click.
  cancelBtn.dataset.nav = 'new';

  $('statIncidentsLabel').textContent = pipeline.incidentsLabel;
  $('statArtifacts').textContent = '0';
  $('statEvents').textContent = '0';
  $('statIncidents').textContent = '0';
  $('statIocs').textContent = '0';
  $('consoleBody').innerHTML = '';
  $('consoleCount').textContent = '0 lines';

  const pipelineEl = $('pipeline');
  pipelineEl.innerHTML = '';
  pipeline.stages.forEach(function (s) {
    pipelineEl.appendChild(buildStageElement(s));
  });

  Router.go('progress');

  state.startTime = Date.now();
  clearInterval(state.elapsedTimer);
  state.elapsedTimer = setInterval(function () {
    const secs = Math.floor((Date.now() - state.startTime) / 1000);
    const m = String(Math.floor(secs / 60)).padStart(2, '0');
    const s = String(secs % 60).padStart(2, '0');
    $('elapsed').textContent = m + ':' + s;
  }, 500);

  runRealPipeline(runType, pipeline);
}
