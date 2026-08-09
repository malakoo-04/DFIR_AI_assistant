/* ============================================================
   progress.js — DFIR-AI frontend
   "Investigation progress" page.

   PIPELINES holds the cosmetic stage/log/stat data used to drive the
   stage timeline and console while a job is running — the backend
   doesn't report fine-grained per-stage progress, so this is what
   fills the UI in between "job started" and "job finished".

   launchPipeline() (new_case.js) calls runRealPipeline(runType,
   pipeline) for 'dfir' and 'ioc': it POSTs /api/report or /api/ioc,
   then polls GET /api/status/{job_id} until the real job completes
   or fails, while the cosmetic animation (same stage DOM / console
   DOM / stat DOM as before) plays underneath, capped just short of
   100% so it never claims "done" before the backend actually is.
   Once the real job completes, GET /api/result/{job_id} supplies the
   real output paths, stored on `state` for results.js.

   runSimulatedPipeline() is kept as-is and still used for 'haya'
   (POST /api/hayabusa is a not-yet-implemented placeholder — see
   runRealPipeline's haya branch below).
   ------------------------------------------------------------ */

// Stage-id helpers — every stage renders three DOM ids derived from
// its own id (stage-<id>, fill-<id>, sub-<id>). Centralized here so
// the "stage-" / "fill-" / "sub-" prefixes exist in exactly one
// place instead of being concatenated at every call site.
function stageId(id) { return 'stage-' + id; }
function fillId(id) { return 'fill-' + id; }
function subId(id) { return 'sub-' + id; }

const PIPELINES = Object.freeze({
  dfir: {
    label: 'Full DFIR pipeline',
    resultTitle: 'DFIR report — full pipeline',
    stages: [
      {id:'upload',    title:'Evidence upload',       sub:'Validating archive integrity'},
      {id:'discover',  title:'Discovery engine',       sub:'Scanning triage structure'},
      {id:'inventory', title:'Inventory',              sub:'Cataloguing candidate artifacts'},
      {id:'parsers',   title:'Artifact parsers',       sub:'Parsing MFT, registry, EVTX, prefetch…'},
      {id:'normalize', title:'Normalization',          sub:'Mapping to unified event schema'},
      {id:'timeline',  title:'Timeline generation',    sub:'Building master super-timeline'},
      {id:'correlate', title:'Correlation engine',     sub:'Clustering related events into incidents'},
      {id:'ai',        title:'AI investigation',       sub:'Drafting incident narrative'},
      {id:'mitre',     title:'MITRE ATT&CK mapping',   sub:'Mapping techniques to tactics'},
      {id:'pdf',       title:'PDF report generation',  sub:'Rendering final report'},
    ],
    logs: [
      {t:0.02, msg:'Mounting evidence container evidence_WKS-14.zip', cls:'info'},
      {t:0.06, msg:'Archive integrity check passed (SHA-256 verified)'},
      {t:0.12, msg:'Discovery engine scanning triage output structure', cls:'info'},
      {t:0.16, msg:'Detected KAPE collection layout (C\\, TriageTemplates)'},
      {t:0.20, msg:'Located 347 candidate artifacts across 19 categories'},
      {t:0.26, msg:'Building artifact inventory index'},
      {t:0.30, msg:'Inventory complete — 347 artifacts queued for parsing'},
      {t:0.34, msg:'Parsing NTFS $MFT … 128,442 records', cls:'info'},
      {t:0.38, msg:'Parsing Prefetch … 214 execution records'},
      {t:0.42, msg:'Parsing Amcache.hve … 891 entries'},
      {t:0.46, msg:'Parsing Windows Event Logs (.evtx) … 12 channels', cls:'info'},
      {t:0.50, msg:'Parsing registry hives: SYSTEM, SOFTWARE, NTUSER.DAT'},
      {t:0.54, msg:'Parsing browser artifacts (history, downloads, cookies)'},
      {t:0.58, msg:'Artifact parsing complete — 611,204 raw events'},
      {t:0.62, msg:'Normalizing events to unified schema', cls:'info'},
      {t:0.66, msg:'Resolving entity identities across sources'},
      {t:0.70, msg:'Building master timeline … 2,184,309 events', cls:'info'},
      {t:0.76, msg:'Running correlation engine — clustering related events', cls:'info'},
      {t:0.82, msg:'Correlation engine generated 3 candidate incidents'},
      {t:0.86, msg:'Sending incident context to investigation AI model', cls:'info'},
      {t:0.90, msg:'AI investigation module drafting incident narrative'},
      {t:0.94, msg:'Mapping identified techniques to MITRE ATT&CK matrix', cls:'info'},
      {t:0.97, msg:'Rendering PDF report'},
      {t:1.00, msg:'DFIR report generation complete', cls:'info'},
    ],
    stats: { artifacts:347, events:2184309, incidents:3, iocs:146 },
    incidentsLabel: 'Generated incidents',
    duration: 9000,
  },
  ioc: {
    label: 'IOC extraction only',
    resultTitle: 'IOC report',
    stages: [
      {id:'upload',    title:'Evidence upload',       sub:'Validating archive integrity'},
      {id:'discover',  title:'Discovery engine',       sub:'Scanning triage structure'},
      {id:'inventory', title:'Inventory',              sub:'Cataloguing candidate artifacts'},
      {id:'parsers',   title:'Artifact parsers',       sub:'Parsing artifacts relevant to indicators'},
      {id:'normalize', title:'Normalization',          sub:'Mapping to unified event schema'},
      {id:'ioc',       title:'IOC extraction',         sub:'Extracting hashes, IPs, domains, paths'},
      {id:'pdf',       title:'IOC report generation',  sub:'Rendering IOC report'},
    ],
    logs: [
      {t:0.03, msg:'Mounting evidence container evidence_WKS-14.zip', cls:'info'},
      {t:0.10, msg:'Archive integrity check passed (SHA-256 verified)'},
      {t:0.18, msg:'Discovery engine scanning triage output structure', cls:'info'},
      {t:0.28, msg:'Located 347 candidate artifacts across 19 categories'},
      {t:0.36, msg:'Inventory complete — 347 artifacts queued for parsing'},
      {t:0.46, msg:'Parsing registry, browser and network-relevant artifacts', cls:'info'},
      {t:0.58, msg:'Artifact parsing complete — 84,112 raw events'},
      {t:0.66, msg:'Normalizing events to unified schema', cls:'info'},
      {t:0.76, msg:'Running IOC extraction module', cls:'info'},
      {t:0.85, msg:'Extracted 146 indicators (39 high confidence)'},
      {t:0.94, msg:'Rendering IOC report'},
      {t:1.00, msg:'IOC report generation complete', cls:'info'},
    ],
    stats: { artifacts:347, events:84112, incidents:0, iocs:146 },
    incidentsLabel: 'High-confidence IOCs',
    duration: 6000,
  },
  haya: {
    label: 'Hayabusa analysis only',
    resultTitle: 'Hayabusa results',
    stages: [
      {id:'upload',    title:'Evidence upload',       sub:'Validating archive integrity'},
      {id:'discover',  title:'Discovery engine',       sub:'Locating Windows Event Log files'},
      {id:'inventory', title:'Inventory',              sub:'Cataloguing .evtx channels'},
      {id:'haya',      title:'Hayabusa rule scan',     sub:'Running Sigma ruleset against EVTX'},
      {id:'correlate', title:'Result correlation',     sub:'Ranking detections by severity'},
      {id:'export',    title:'Results export',         sub:'Generating CSV / JSON output'},
    ],
    logs: [
      {t:0.04, msg:'Mounting evidence container evidence_WKS-14.zip', cls:'info'},
      {t:0.14, msg:'Archive integrity check passed (SHA-256 verified)'},
      {t:0.24, msg:'Discovery engine locating .evtx files', cls:'info'},
      {t:0.34, msg:'Found 12 Windows Event Log channels (612 MB)'},
      {t:0.44, msg:'Inventory complete — queued for Hayabusa scan'},
      {t:0.54, msg:'Launching Hayabusa with full Sigma ruleset', cls:'info'},
      {t:0.66, msg:'Scanning Security.evtx … 214,880 records'},
      {t:0.74, msg:'Scanning Microsoft-Windows-PowerShell%4Operational.evtx'},
      {t:0.82, msg:'Hayabusa scan complete — 58 detections', cls:'info'},
      {t:0.90, msg:'Ranking detections by severity (4 critical, 11 high)'},
      {t:0.97, msg:'Exporting results to CSV and JSON'},
      {t:1.00, msg:'Hayabusa analysis complete', cls:'info'},
    ],
    stats: { artifacts:12, events:214880, incidents:58, iocs:0 },
    incidentsLabel: 'Detections found',
    duration: 6500,
  }
});

/* ------------------------------------------------------------
   Simulation runner (placeholder — see note above PIPELINES)
   Called by launchPipeline() in new_case.js once the progress
   page UI is set up. This is the one function to swap out when
   the real backend is wired in.
   ------------------------------------------------------------ */
function runSimulatedPipeline(pipeline) {
  const totalDuration = pipeline.duration;
  const stages = pipeline.stages;
  const nStages = stages.length;
  let currentStageIdx = -1;
  let logIdx = 0;
  const startedAt = Date.now();
  let loggedCount = 0;

  clearInterval(state.timer);
  state.timer = setInterval(function () {
    const elapsed = Date.now() - startedAt;
    const progress = Math.min(elapsed / totalDuration, 1);

    $('progFill').style.width = (progress * 100).toFixed(0) + '%';
    $('progPercent').textContent = Math.round(progress * 100) + '%';

    const targetStageIdx = Math.min(Math.floor(progress * nStages), nStages - 1);
    if (targetStageIdx > currentStageIdx) {
      markStage(targetStageIdx, stages, progress >= 1);
      currentStageIdx = targetStageIdx;
      $('progStageLabel').textContent = stages[currentStageIdx].title + '…';
    }

    const st = pipeline.stats;
    $('statArtifacts').textContent =
      Math.round(st.artifacts * Math.min(progress * 2.2, 1)).toLocaleString();
    $('statEvents').textContent =
      Math.round(st.events * Math.max(0, Math.min((progress - 0.25) * 1.6, 1))).toLocaleString();
    $('statIncidents').textContent =
      Math.round(st.incidents * Math.max(0, Math.min((progress - 0.6) * 2.6, 1))).toLocaleString();
    $('statIocs').textContent =
      Math.round(st.iocs * Math.max(0, Math.min((progress - 0.55) * 2.3, 1))).toLocaleString();

    while (logIdx < pipeline.logs.length && pipeline.logs[logIdx].t <= progress) {
      appendLog(pipeline.logs[logIdx]);
      logIdx++;
      loggedCount++;
      $('consoleCount').textContent = loggedCount + ' lines';
    }

    if (progress >= 1) {
      clearInterval(state.timer);
      stages.forEach(function (s) { setStageDone(s.id); });
      $('progStageLabel').textContent = 'Complete';
      $('progBadge').className = 'prog-status-badge done';
      $('progBadgeText').textContent = 'Complete';
      $('progViewResults').style.display = 'inline-flex';

      const cancelBtn = $('progCancelBtn');
      cancelBtn.textContent = 'Back to home';
      // Retarget the existing data-nav binding instead of assigning
      // a new .onclick — Router's generic listener re-reads
      // dataset.nav on every click, so just changing the attribute
      // is enough.
      cancelBtn.dataset.nav = 'home';

      clearInterval(state.elapsedTimer);
      prepareResults(pipeline);
    }
  }, 120);
}

/* ------------------------------------------------------------
   Real pipeline runner — dfir / ioc.
   Kicks off the actual backend job, then drives the exact same
   stage/console/stat UI as runSimulatedPipeline() while polling
   GET /api/status/{job_id}. Progress is cosmetic (capped at 92%)
   until the backend reports "completed"; only then do we jump to
   100%, mark everything done, and hand off to prepareResults().
   ------------------------------------------------------------ */
function runRealPipeline(runType, pipeline) {
  const endpoint = runType === 'dfir' ? '/api/report'
    : runType === 'ioc' ? '/api/ioc'
    : '/api/hayabusa';

  const totalDuration = pipeline.duration;
  const stages = pipeline.stages;
  const nStages = stages.length;
  let currentStageIdx = -1;
  let logIdx = 0;
  const startedAt = Date.now();
  let loggedCount = 0;

  let jobId = null;
  let jobDone = false;
  let jobFailed = false;
  let jobErrorMsg = null;

  function fail(message) {
    jobFailed = true;
    jobErrorMsg = message;
  }

  function pollStatus() {
    apiGet('/api/status/' + jobId).then(function (res) {
      if (res.status === 'completed') {
        return apiGet('/api/result/' + jobId).then(function (result) {
          state.jobId = jobId;
          state.resultPaths = result;
          jobDone = true;
        });
      }
      if (res.status === 'failed') {
        fail('Pipeline failed on the server. Check the API logs for details.');
        return;
      }
      // queued | running — keep polling.
      setTimeout(pollStatus, 2000);
    }).catch(function (err) {
      fail('Lost contact with the API: ' + err.message);
    });
  }

  apiPost(endpoint, {}).then(function (res) {
    if (res.status === 'not_implemented') {
      fail('Hayabusa backend is not implemented yet.');
      return;
    }
    jobId = res.job_id;
    pollStatus();
  }).catch(function (err) {
    fail('Could not start the job: ' + err.message);
  });

  clearInterval(state.timer);
  state.timer = setInterval(function () {
    const elapsed = Date.now() - startedAt;
    // Cosmetic progress never reaches 100% on its own — it waits
    // for the real job to report completion.
    const progress = jobDone ? 1 : Math.min(elapsed / totalDuration, 0.92);

    $('progFill').style.width = (progress * 100).toFixed(0) + '%';
    $('progPercent').textContent = Math.round(progress * 100) + '%';

    const targetStageIdx = Math.min(Math.floor(progress * nStages), nStages - 1);
    if (targetStageIdx > currentStageIdx) {
      markStage(targetStageIdx, stages, progress >= 1);
      currentStageIdx = targetStageIdx;
      $('progStageLabel').textContent = jobDone ? 'Complete' : stages[currentStageIdx].title + '…';
    }

    const st = pipeline.stats;
    $('statArtifacts').textContent =
      Math.round(st.artifacts * Math.min(progress * 2.2, 1)).toLocaleString();
    $('statEvents').textContent =
      Math.round(st.events * Math.max(0, Math.min((progress - 0.25) * 1.6, 1))).toLocaleString();
    $('statIncidents').textContent =
      Math.round(st.incidents * Math.max(0, Math.min((progress - 0.6) * 2.6, 1))).toLocaleString();
    $('statIocs').textContent =
      Math.round(st.iocs * Math.max(0, Math.min((progress - 0.55) * 2.3, 1))).toLocaleString();

    while (logIdx < pipeline.logs.length && pipeline.logs[logIdx].t <= progress) {
      appendLog(pipeline.logs[logIdx]);
      logIdx++;
      loggedCount++;
      $('consoleCount').textContent = loggedCount + ' lines';
    }

    if (jobFailed) {
      clearInterval(state.timer);
      clearInterval(state.elapsedTimer);
      appendLog({ msg: jobErrorMsg || 'Pipeline failed.', cls: 'warn' });
      $('progStageLabel').textContent = 'Failed';
      $('progBadgeText').textContent = 'Failed';

      const cancelBtn = $('progCancelBtn');
      cancelBtn.textContent = 'Back to setup';
      cancelBtn.dataset.nav = 'new';
      return;
    }

    if (jobDone) {
      clearInterval(state.timer);
      stages.forEach(function (s) { setStageDone(s.id); });
      $('progStageLabel').textContent = 'Complete';
      $('progBadge').className = 'prog-status-badge done';
      $('progBadgeText').textContent = 'Complete';
      $('progViewResults').style.display = 'inline-flex';

      const cancelBtn = $('progCancelBtn');
      cancelBtn.textContent = 'Back to home';
      cancelBtn.dataset.nav = 'home';

      clearInterval(state.elapsedTimer);
      prepareResults(pipeline);
    }
  }, 120);
}

function markStage(idx, stages, finalPass) {
  for (let i = 0; i < idx; i++) setStageDone(stages[i].id);
  const s = stages[idx];
  const el = $(stageId(s.id));
  if (!el) return;

  if (finalPass) {
    setStageDone(s.id);
  } else {
    el.classList.remove('done');
    el.classList.add('running');
    const sub = $(subId(s.id));
    const fill = $(fillId(s.id));
    if (sub) sub.textContent = s.sub;
    if (fill) fill.style.height = '100%';
  }
}

function setStageDone(id) {
  const el = $(stageId(id));
  if (!el) return;
  el.classList.remove('running');
  el.classList.add('done');
  const fill = $(fillId(id));
  if (fill) fill.style.height = '100%';
}

// Builds one pipeline-stage DOM node without innerHTML — mirrors the
// markup that used to be assembled as an HTML string:
//   <div class="pipe-stage" id="stage-<id>">
//     <div class="pipe-line"><div class="pipe-line-fill" id="fill-<id>"></div></div>
//     <div class="pipe-node"><svg viewBox="0 0 24 24"><use href="#i-check"/></svg></div>
//     <div class="pipe-title"><id/>title></div>
//     <div class="pipe-sub" id="sub-<id>"></div>
//   </div>
const SVG_NS = 'http://www.w3.org/2000/svg';

function buildStageElement(stage) {
  const div = document.createElement('div');
  div.className = 'pipe-stage';
  div.id = stageId(stage.id);

  const line = document.createElement('div');
  line.className = 'pipe-line';
  const lineFill = document.createElement('div');
  lineFill.className = 'pipe-line-fill';
  lineFill.id = fillId(stage.id);
  line.appendChild(lineFill);

  const node = document.createElement('div');
  node.className = 'pipe-node';
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#i-check');
  svg.appendChild(use);
  node.appendChild(svg);

  const title = document.createElement('div');
  title.className = 'pipe-title';
  title.textContent = stage.title;

  const sub = document.createElement('div');
  sub.className = 'pipe-sub';
  sub.id = subId(stage.id);

  div.append(line, node, title, sub);
  return div;
}

function appendLog(logEntry) {
  const body = $('consoleBody');
  if (!body) return;
  const ts = new Date().toTimeString().slice(0, 8);

  const line = document.createElement('div');
  line.className = 'log-line';

  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = '[' + ts + ']';

  const text = document.createElement('span');
  text.className = logEntry.cls ? 'log-text ' + logEntry.cls : 'log-text';
  text.textContent = logEntry.msg;

  line.append(time, text);
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
}
