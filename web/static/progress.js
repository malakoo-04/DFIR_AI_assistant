/* ============================================================
   progress.js — DFIR-AI frontend
   "Investigation progress" page.

   PIPELINES holds the cosmetic stage/stat data used to drive the
   stage timeline while a job is running — the backend doesn't report
   fine-grained per-stage progress, so this fills the UI in between
   "job started" and "job finished". The console panel itself is NOT
   cosmetic: it streams the real print() output of the running
   pipeline via GET /api/logs/{job_id} (see pollLogs() below), and
   stat counters (artifacts / incidents / IOCs) are updated from real
   numbers parsed out of that output as soon as they appear, falling
   back to the cosmetic ramp only until real data arrives.

   launchPipeline() (new_case.js) calls runRealPipeline(runType,
   pipeline) for every run type: it POSTs /api/report, /api/ioc or
   /api/hayabusa, then polls GET /api/status/{job_id} until the job
   completes or fails, while the cosmetic stage animation (capped
   just short of 100% so it never claims "done" before the backend
   actually is) plays underneath. Once the real job completes,
   GET /api/result/{job_id} supplies the real output paths, stored on
   `state` for results.js. Hayabusa (POST /api/hayabusa) is a
   not-yet-implemented placeholder on the backend and fails
   immediately with "Not implemented yet".
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
    stats: { artifacts:12, events:214880, incidents:58, iocs:0 },
    incidentsLabel: 'Detections found',
    duration: 6500,
  }
});

/* ------------------------------------------------------------
   Real pipeline runner — dfir / ioc / haya.
   Kicks off the actual backend job, then drives the stage/stat UI
   while polling GET /api/status/{job_id}. Progress is cosmetic
   (capped at 92%) until the backend reports "completed"; only then
   do we jump to 100%, mark everything done, and hand off to
   prepareResults(). The console panel is NOT cosmetic: pollLogs()
   streams the real print() output of the running job from
   GET /api/logs/{job_id}, and any artifact/incident/IOC counts found
   in that real output override the cosmetic stat ramp.
   ------------------------------------------------------------ */

// Recognizes the pipeline's own count lines, e.g.
// "Recognized artifacts: 347", "Incidents generated: 815",
// "Candidate IOCs: 1779", "IOCs extracted: 146" — see
// modules/discovery/scanner.py, modules/ioc/candidate_ioc_collector.py,
// scripts/run_final_report.py and scripts/run_ioc_extraction.py.
const LOG_STAT_PATTERNS = [
  { statId: 'statArtifacts', re: /Recognized artifacts:\s*([\d,]+)/i },
  { statId: 'statIncidents', re: /Incidents generated:\s*([\d,]+)/i },
  { statId: 'statIocs',      re: /Candidate IOCs:\s*([\d,]+)/i },
  { statId: 'statIocs',      re: /IOCs extracted:\s*([\d,]+)/i },
];

function applyLogStats(line) {
  LOG_STAT_PATTERNS.forEach(function (p) {
    const m = line.match(p.re);
    if (m) $(p.statId).textContent = m[1];
  });
}

function classifyLogLine(line) {
  if (/error|failed|exception|traceback/i.test(line)) return 'warn';
  if (/waiting .* seconds|quota/i.test(line)) return 'warn';
  return 'info';
}

// Appends one real backend log line. The server already prefixes
// each line with "[HH:MM:SS] " (see api/pipeline_runner.py); split
// that off so it renders in the same .log-time / .log-text structure
// the console panel's CSS already styles.
const LOG_TS_PREFIX = /^\[(\d{2}:\d{2}:\d{2})\]\s?/;

function appendRealLog(line, consoleCountRef) {
  const body = $('consoleBody');
  if (body) {
    const m = line.match(LOG_TS_PREFIX);
    const ts = m ? '[' + m[1] + ']' : '';
    const rest = m ? line.slice(m[0].length) : line;

    const div = document.createElement('div');
    div.className = 'log-line';

    if (ts) {
      const time = document.createElement('span');
      time.className = 'log-time';
      time.textContent = ts;
      div.appendChild(time);
    }

    const text = document.createElement('span');
    text.className = 'log-text ' + classifyLogLine(line);
    text.textContent = rest;
    div.appendChild(text);

    body.appendChild(div);
    body.scrollTop = body.scrollHeight;
  }
  consoleCountRef.n++;
  $('consoleCount').textContent = consoleCountRef.n + ' lines';
  applyLogStats(line);
}

// Re-enables the New Investigation run buttons (disabled by
// launchPipeline() in new_case.js to prevent duplicate submissions)
// once a run finishes, one way or another.
function releaseRunLock() {
  state.runInFlight = false;
  if (typeof validateForm === 'function') validateForm();
}

function runRealPipeline(runType, pipeline) {
  const myGen = state.runGen;
  const endpoint = runType === 'dfir' ? '/api/report'
    : runType === 'ioc' ? '/api/ioc'
    : '/api/hayabusa';

  const totalDuration = pipeline.duration;
  const stages = pipeline.stages;
  const nStages = stages.length;
  let currentStageIdx = -1;
  const startedAt = Date.now();
  const consoleCount = { n: 0 };

  let jobId = null;
  let jobDone = false;
  let jobFailed = false;
  let jobErrorMsg = null;
  let logsSince = 0;

  function fail(message) {
    jobFailed = true;
    jobErrorMsg = message;
  }

  function pollStatus() {
    if (state.runGen !== myGen) return; // superseded by a newer run
    apiGet('/api/status/' + jobId).then(function (res) {
      if (state.runGen !== myGen) return;
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

  // Streams the job's real console output into the log panel, one
  // second at a time, until the job finishes (successfully or not).
  function pollLogs() {
    if (state.runGen !== myGen || !jobId || jobDone || jobFailed) return;
    apiGet('/api/logs/' + jobId + '?since=' + logsSince).then(function (res) {
      if (state.runGen !== myGen) return;
      logsSince = res.next_offset;
      res.logs.forEach(function (line) { appendRealLog(line, consoleCount); });
      if (!jobDone && !jobFailed) setTimeout(pollLogs, 1000);
    }).catch(function () {
      // Transient poll failure — don't kill the run over a missed
      // log fetch, just try again shortly.
      if (state.runGen === myGen && !jobDone && !jobFailed) setTimeout(pollLogs, 1000);
    });
  }

  apiPost(endpoint, {}).then(function (res) {
    if (res.status === 'not_implemented') {
      fail('Hayabusa backend is not implemented yet.');
      return;
    }
    jobId = res.job_id;
    pollStatus();
    pollLogs();
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

    // Cosmetic ramp — overwritten by applyLogStats() the moment the
    // real pipeline prints an actual count for that stat.
    const st = pipeline.stats;
    $('statArtifacts').textContent =
      Math.round(st.artifacts * Math.min(progress * 2.2, 1)).toLocaleString();
    $('statEvents').textContent =
      Math.round(st.events * Math.max(0, Math.min((progress - 0.25) * 1.6, 1))).toLocaleString();
    $('statIncidents').textContent =
      Math.round(st.incidents * Math.max(0, Math.min((progress - 0.6) * 2.6, 1))).toLocaleString();
    $('statIocs').textContent =
      Math.round(st.iocs * Math.max(0, Math.min((progress - 0.55) * 2.3, 1))).toLocaleString();

    if (jobFailed) {
      clearInterval(state.timer);
      clearInterval(state.elapsedTimer);
      appendRealLog(jobErrorMsg || 'Pipeline failed.', consoleCount);
      $('progStageLabel').textContent = 'Failed';
      $('progBadgeText').textContent = 'Failed';

      const cancelBtn = $('progCancelBtn');
      cancelBtn.textContent = 'Back to setup';
      cancelBtn.dataset.nav = 'new';
      releaseRunLock();
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
      releaseRunLock();
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


