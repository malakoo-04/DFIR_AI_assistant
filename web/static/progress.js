/* ============================================================
   progress.js — DFIR-AI frontend
   "Investigation progress" page.

   Pure visualization of backend state. Nothing on this page is
   timer-driven or interpolated anymore:

     - GET /api/status/{job_id} returns {job_id, status, phase,
       stats}.
     - Every poll re-renders the stage list and stat cards from
       the real backend response.
     - The console streams real backend lines from
       GET /api/logs/{job_id}.
     - Hayabusa runs independently and produces its own CSV.

   IMPORTANT:
   The log polling has a final fetch after the backend reports
   "completed". This prevents the status request from winning the
   race against the log request and hiding the final Hayabusa
   statistics/output lines.
   ------------------------------------------------------------ */

function stageId(id) {
  return 'stage-' + id;
}

function fillId(id) {
  return 'fill-' + id;
}

function subId(id) {
  return 'sub-' + id;
}


const PIPELINES = Object.freeze({

  dfir: {
    label: 'Full DFIR pipeline',
    resultTitle: 'DFIR report — full pipeline',
    incidentsLabel: 'Generated incidents',

    stages: [
      {
        id: 'upload',
        phase: null,
        title: 'Evidence upload',
        sub: 'Archive received and validated'
      },
      {
        id: 'discovery',
        phase: 'DISCOVERY',
        title: 'Discovery engine',
        sub: 'Scanning triage structure'
      },
      {
        id: 'inventory',
        phase: 'INVENTORY',
        title: 'Inventory',
        sub: 'Cataloguing candidate artifacts'
      },
      {
        id: 'parsers',
        phase: 'PARSERS',
        title: 'Artifact parsers',
        sub: 'Parsing MFT, registry, EVTX, prefetch…'
      },
      {
        id: 'normalization',
        phase: 'NORMALIZATION',
        title: 'Normalization',
        sub: 'Mapping to unified event schema'
      },
      {
        id: 'timeline',
        phase: 'TIMELINE',
        title: 'Timeline generation',
        sub: 'Building master super-timeline'
      },
      {
        id: 'correlation',
        phase: 'CORRELATION',
        title: 'Correlation engine',
        sub: 'Clustering related events into incidents'
      },
      {
        id: 'mitre',
        phase: 'MITRE',
        title: 'MITRE ATT&CK mapping',
        sub: 'Mapping techniques to tactics'
      },
      {
        id: 'investigation',
        phase: 'INVESTIGATION',
        title: 'AI investigation',
        sub: 'Drafting incident narrative'
      },
      {
        id: 'ioc_extraction',
        phase: 'IOC_EXTRACTION',
        title: 'IOC extraction',
        sub: 'Extracting hashes, IPs, domains, paths'
      },
      {
        id: 'ioc_report',
        phase: 'IOC_REPORT',
        title: 'IOC report',
        sub: 'Validating IOC report'
      },
      {
        id: 'final_report',
        phase: 'FINAL_REPORT',
        title: 'Final report',
        sub: 'Drafting final DFIR report'
      }
    ],

    duration: 9000
  },


  ioc: {
    label: 'IOC extraction only',
    resultTitle: 'IOC report',
    incidentsLabel: 'Candidate IOCs',

    stages: [
      {
        id: 'upload',
        phase: null,
        title: 'Evidence upload',
        sub: 'Archive received and validated'
      },
      {
        id: 'discovery',
        phase: 'DISCOVERY',
        title: 'Discovery engine',
        sub: 'Scanning triage structure'
      },
      {
        id: 'inventory',
        phase: 'INVENTORY',
        title: 'Inventory',
        sub: 'Cataloguing candidate artifacts'
      },
      {
        id: 'parsers',
        phase: 'PARSERS',
        title: 'Artifact parsers',
        sub: 'Parsing artifacts relevant to indicators'
      },
      {
        id: 'normalization',
        phase: 'NORMALIZATION',
        title: 'Normalization',
        sub: 'Mapping to unified event schema'
      },
      {
        id: 'timeline',
        phase: 'TIMELINE',
        title: 'Timeline generation',
        sub: 'Building master timeline'
      },
      {
        id: 'correlation',
        phase: 'CORRELATION',
        title: 'Correlation engine',
        sub: 'Clustering related events into incidents'
      },
      {
        id: 'ioc_extraction',
        phase: 'IOC_EXTRACTION',
        title: 'IOC extraction',
        sub: 'Extracting hashes, IPs, domains, paths'
      },
      {
        id: 'ioc_report',
        phase: 'IOC_REPORT',
        title: 'IOC report',
        sub: 'Validating and saving IOC report'
      }
    ],

    duration: 6000
  },


  haya: {
    label: 'Hayabusa analysis only',
    resultTitle: 'Hayabusa results',

    stages: [
      {
        id: 'upload',
        phase: null,
        title: 'Evidence upload',
        sub: 'Archive received and validated'
      },
      {
        id: 'discovery',
        phase: 'DISCOVERY',
        title: 'EVTX discovery',
        sub: 'Finding Windows Event Log files'
      },
      {
        id: 'scan_init',
        phase: 'HAYABUSA_SCAN',
        title: 'Hayabusa initialization',
        sub: 'Loading rules and preparing the EVTX scan'
      },
      {
        id: 'scanning',
        phase: 'SCANNING',
        title: 'EVTX analysis',
        sub: 'Scanning Event Logs with Hayabusa'
      },
      {
        id: 'saving',
        phase: 'SAVING_RESULTS',
        title: 'Results export',
        sub: 'Writing the independent Hayabusa CSV'
      }
    ]
  }

});


const STAT_CARD_CONFIG = {

  dfir: [
    {
      elId: 'statArtifacts',
      statKey: 'artifacts_discovered'
    },
    {
      elId: 'statEvents',
      statKey: 'parsed_events'
    },
    {
      elId: 'statIncidents',
      statKey: 'incidents_generated'
    },
    {
      elId: 'statIocs',
      statKey: 'confirmed_iocs'
    }
  ],

  ioc: [
    {
      elId: 'statArtifacts',
      statKey: 'artifacts_discovered'
    },
    {
      elId: 'statEvents',
      statKey: 'parsed_events'
    },
    {
      elId: 'statIncidents',
      statKey: 'candidate_iocs'
    },
    {
      elId: 'statIocs',
      statKey: 'confirmed_iocs'
    }
  ],

  haya: [
    {
      elId: 'statArtifacts',
      statKey: 'evtx_files_found'
    },
    {
      elId: 'statEvents',
      statKey: 'evtx_files_loaded'
    }
  ]

};


function classifyLogLine(line) {

  if (
    /error|failed|exception|traceback/i.test(line)
  ) {
    return 'warn';
  }

  if (
    /waiting .* seconds|quota/i.test(line)
  ) {
    return 'warn';
  }

  return 'info';
}


const LOG_TS_PREFIX =
  /^\[(\d{2}:\d{2}:\d{2})\]\s?/;


function appendRealLog(line, consoleCountRef) {

  const body = $('consoleBody');

  if (body) {

    const m =
      line.match(LOG_TS_PREFIX);

    const ts =
      m
        ? '[' + m[1] + ']'
        : '';

    const rest =
      m
        ? line.slice(m[0].length)
        : line;

    const div =
      document.createElement('div');

    div.className =
      'log-line';


    if (ts) {

      const time =
        document.createElement('span');

      time.className =
        'log-time';

      time.textContent =
        ts;

      div.appendChild(time);
    }


    const text =
      document.createElement('span');

    text.className =
      'log-text ' +
      classifyLogLine(line);

    text.textContent =
      rest;

    div.appendChild(text);


    body.appendChild(div);

    body.scrollTop =
      body.scrollHeight;
  }


  consoleCountRef.n++;

  $('consoleCount').textContent =
    consoleCountRef.n + ' lines';
}


function releaseRunLock() {

  state.runInFlight = false;

  if (
    typeof validateForm === 'function'
  ) {
    validateForm();
  }
}


/* ------------------------------------------------------------
   Stage + stat rendering
   ------------------------------------------------------------ */

function resetStagesAndStats(
  stages,
  statCards,
  runType
) {

  stages.forEach(function (s) {

    const el =
      $(stageId(s.id));

    if (el) {
      el.classList.remove(
        'done',
        'running'
      );
    }


    const sub =
      $(subId(s.id));

    if (sub) {
      sub.textContent =
        s.sub;
    }


    const fill =
      $(fillId(s.id));

    if (fill) {
      fill.style.height =
        '0%';
    }

  });


  stages.forEach(function (s) {

    if (!s.phase) {
      setStageDone(s.id);
    }

  });


  const statsRow =
    $('statsRow');

  const incidentsCard =
    $('statIncidents')
      ?.closest('.stat-card');

  const iocsCard =
    $('statIocs')
      ?.closest('.stat-card');


  if (runType === 'haya') {

    if (statsRow) {
      statsRow.classList.add(
        'hayabusa-stats'
      );
    }


    if (incidentsCard) {
      incidentsCard.style.display =
        'none';
    }


    if (iocsCard) {
      iocsCard.style.display =
        'none';
    }


    const artifactsLabel =
      document
        .querySelector('#statArtifacts')
        ?.closest('.stat-card')
        ?.querySelector('.stat-label span');


    const eventsLabel =
      document
        .querySelector('#statEvents')
        ?.closest('.stat-card')
        ?.querySelector('.stat-label span');


    if (artifactsLabel) {
      artifactsLabel.textContent =
        'EVTX files found';
    }


    if (eventsLabel) {
      eventsLabel.textContent =
        'EVTX files analyzed';
    }


  } else {

    if (statsRow) {
      statsRow.classList.remove(
        'hayabusa-stats'
      );
    }


    if (incidentsCard) {
      incidentsCard.style.display =
        '';
    }


    if (iocsCard) {
      iocsCard.style.display =
        '';
    }


    const artifactsLabel =
      document
        .querySelector('#statArtifacts')
        ?.closest('.stat-card')
        ?.querySelector('.stat-label span');


    const eventsLabel =
      document
        .querySelector('#statEvents')
        ?.closest('.stat-card')
        ?.querySelector('.stat-label span');


    if (artifactsLabel) {
      artifactsLabel.textContent =
        'Artifacts discovered';
    }


    if (eventsLabel) {
      eventsLabel.textContent =
        'Parsed events';
    }

  }


  statCards.forEach(function (c) {

    const el =
      $(c.elId);

    if (el) {
      el.textContent =
        '--';
    }

  });


  $('progFill').style.width =
    '0%';

  $('progPercent').textContent =
    '0%';

  $('progStageLabel').textContent =
    'Queued…';
}


function setStageDone(id) {

  const el =
    $(stageId(id));

  if (!el) {
    return;
  }


  el.classList.remove(
    'running'
  );

  el.classList.add(
    'done'
  );


  const fill =
    $(fillId(id));

  if (fill) {
    fill.style.height =
      '100%';
  }
}


function renderStages(
  stages,
  phase,
  jobDone
) {

  if (jobDone) {

    stages.forEach(function (s) {
      setStageDone(s.id);
    });

    return;
  }


  if (!phase) {
    return;
  }


  let reachedCurrent =
    false;


  stages.forEach(function (s) {

    if (!s.phase) {
      return;
    }


    if (s.phase === phase) {

      reachedCurrent =
        true;


      const el =
        $(stageId(s.id));

      if (el) {

        el.classList.remove(
          'done'
        );

        el.classList.add(
          'running'
        );
      }


      const fill =
        $(fillId(s.id));

      if (fill) {
        fill.style.height =
          '100%';
      }


    } else if (!reachedCurrent) {

      setStageDone(
        s.id
      );

    }

  });
}


function renderProgressPercent(
  realPhases,
  phase,
  jobDone
) {

  let pct =
    0;


  if (jobDone) {

    pct =
      100;

  } else if (phase) {

    const idx =
      realPhases.indexOf(
        phase
      );

    if (idx >= 0) {

      pct =
        Math.round(
          (idx / realPhases.length) *
          100
        );

    }

  }


  $('progFill').style.width =
    pct + '%';

  $('progPercent').textContent =
    pct + '%';
}


function renderStatCards(
  statCards,
  stats
) {

  statCards.forEach(function (c) {

    const el =
      $(c.elId);

    if (!el) {
      return;
    }


    const has =
      stats &&
      Object.prototype.hasOwnProperty.call(
        stats,
        c.statKey
      );


    el.textContent =
      has
        ? Number(
            stats[c.statKey]
          ).toLocaleString()
        : '--';

  });
}


function renderStageLabel(
  stages,
  phase,
  jobDone,
  runType
) {

  if (jobDone) {

    $('progStageLabel').textContent =
      runType === 'haya'
        ? '✔ Hayabusa analysis completed'
        : '✔ Investigation completed';

    return;
  }


  if (!phase) {

    $('progStageLabel').textContent =
      'Queued…';

    return;
  }


  const active =
    stages.find(function (s) {
      return s.phase === phase;
    });


  $('progStageLabel').textContent =
    active
      ? active.title + '…'
      : phase;
}


/* ------------------------------------------------------------
   REAL PIPELINE RUNNER
   ------------------------------------------------------------ */

function runRealPipeline(
  runType,
  pipeline
) {

  const myGen =
    state.runGen;


  const endpoint =
    runType === 'dfir'
      ? '/api/report'
      : runType === 'ioc'
        ? '/api/ioc'
        : '/api/hayabusa';


  const stages =
    pipeline.stages;


  const realPhases =
    stages
      .filter(function (s) {
        return s.phase;
      })
      .map(function (s) {
        return s.phase;
      });


  const statCards =
    STAT_CARD_CONFIG[runType] || [];


  const consoleCount =
    { n: 0 };


  let jobId =
    null;

  let jobDone =
    false;

  let jobFailed =
    false;

  let jobErrorMsg =
    null;

  let logsSince =
    0;


  resetStagesAndStats(
    stages,
    statCards,
    runType
  );


  $('progTitle').textContent =
    runType === 'haya'
      ? 'Hayabusa analysis in progress'
      : 'Investigation in progress';


  $('progRunLabel').textContent =
    pipeline.label;


  function fail(message) {

    jobFailed =
      true;

    jobErrorMsg =
      message;
  }


  function finish() {

    clearInterval(
      state.elapsedTimer
    );


    if (jobFailed) {

      appendRealLog(
        jobErrorMsg ||
        'Pipeline failed.',
        consoleCount
      );


      $('progStageLabel').textContent =
        'Failed';


      $('progBadgeText').textContent =
        'Failed';


      const cancelBtn =
        $('progCancelBtn');


      cancelBtn.textContent =
        'Back to setup';


      cancelBtn.dataset.nav =
        'new';


      releaseRunLock();

      return;
    }


    if (jobDone) {

      $('progBadge').className =
        'prog-status-badge done';


      $('progBadgeText').textContent =
        'Complete';


      $('progViewResults').style.display =
        'inline-flex';


      const cancelBtn =
        $('progCancelBtn');


      cancelBtn.textContent =
        'Back to home';


      cancelBtn.dataset.nav =
        'home';


      releaseRunLock();


      prepareResults(
        pipeline
      );
    }
  }


  function pollStatus() {

    if (
      state.runGen !== myGen ||
      !jobId
    ) {
      return;
    }


    apiGet(
      '/api/status/' +
      jobId
    )

      .then(function (res) {

        if (
          state.runGen !== myGen
        ) {
          return;
        }


        /*
         * Always use structured backend
         * statistics.
         */
        state.jobStats =
          res.stats || {};


        renderStatCards(
          statCards,
          state.jobStats
        );


        renderStages(
          stages,
          res.phase,
          res.status === 'completed'
        );


        renderProgressPercent(
          realPhases,
          res.phase,
          res.status === 'completed'
        );


        renderStageLabel(
          stages,
          res.phase,
          res.status === 'completed',
          runType
        );


        /* --------------------------------
           COMPLETED
           -------------------------------- */

        if (
          res.status === 'completed'
        ) {

          /*
           * First retrieve the actual result
           * information.
           */
          return apiGet(
            '/api/result/' +
            jobId
          )

            .then(function (result) {

              if (
                state.runGen !== myGen
              ) {
                return;
              }


              state.jobId =
                jobId;


              state.resultPaths =
                result;


              /*
               * Mark the backend job done,
               * but DON'T finish the UI yet.
               */
              jobDone =
                true;


              /*
               * CRITICAL:
               *
               * Fetch the final log batch before
               * calling finish().
               *
               * This fixes the race where the
               * status request says "completed"
               * while the final Hayabusa output
               * hasn't been displayed yet.
               */
              return pollLogs(
                true
              )

                .then(function () {

                  if (
                    state.runGen !== myGen
                  ) {
                    return;
                  }


                  finish();

                });

            });

        }


        /* --------------------------------
           FAILED
           -------------------------------- */

        if (
          res.status === 'failed'
        ) {

          fail(
            'Pipeline failed on the server. Check the API logs for details.'
          );


          finish();

          return;
        }


        /*
         * queued | running
         */
        setTimeout(
          pollStatus,
          1000
        );

      })

      .catch(function (err) {

        if (
          state.runGen !== myGen
        ) {
          return;
        }


        fail(
          'Lost contact with the API: ' +
          err.message
        );


        finish();

      });
  }


  /* ------------------------------------------------------------
     REAL LOG POLLING

     finalFetch=true:
       Used once after the backend reports completed.

     This function returns a Promise specifically so the status
     poll can wait for the final logs before showing COMPLETE.
     ------------------------------------------------------------ */

  function pollLogs(
    finalFetch
  ) {

    finalFetch =
      finalFetch === true;


    if (
      state.runGen !== myGen ||
      !jobId ||
      jobFailed
    ) {

      return Promise.resolve();

    }


    return apiGet(
      '/api/logs/' +
      jobId +
      '?since=' +
      logsSince
    )

      .then(function (res) {

        if (
          state.runGen !== myGen
        ) {
          return;
        }


        const previousOffset =
          logsSince;


        /*
         * Keep the current offset if the API
         * doesn't provide a valid one.
         */
        if (
          Number.isFinite(
            Number(
              res.next_offset
            )
          )
        ) {

          logsSince =
            Number(
              res.next_offset
            );

        }


        const logLines =
          Array.isArray(res.lines)
            ? res.lines
            : (
                Array.isArray(res.logs)
                  ? res.logs
                  : []
              );


        logLines.forEach(
          function (entry) {

            const text =
              typeof entry === 'string'
                ? entry
                : entry &&
                  entry.text;


            if (text) {

              appendRealLog(
                text,
                consoleCount
              );

            }

          }
        );


        /*
         * FINAL FETCH
         *
         * If new log data arrived, make one
         * additional request to ensure we have
         * consumed the final batch.
         */
        if (finalFetch) {

          if (
            logsSince !== previousOffset &&
            logLines.length > 0
          ) {

            return pollLogs(
              true
            );

          }


          return;

        }


        /*
         * NORMAL POLLING
         */
        if (
          !jobDone &&
          !jobFailed
        ) {

          setTimeout(
            function () {
              pollLogs(false);
            },
            1000
          );

        }

      })

      .catch(function (err) {

        /*
         * Log polling failure must NOT fail
         * the actual Hayabusa/DFIR job.
         */

        if (
          !finalFetch &&
          state.runGen === myGen &&
          !jobDone &&
          !jobFailed
        ) {

          setTimeout(
            function () {
              pollLogs(false);
            },
            1000
          );

        }


        if (finalFetch) {

          console.warn(
            'Final log fetch failed:',
            err
          );

        }

      });

  }


  /* ------------------------------------------------------------
     START BACKEND JOB
     ------------------------------------------------------------ */

  apiPost(
    endpoint,
    {}
  )

    .then(function (res) {

      if (
        res.status ===
        'not_implemented'
      ) {

        fail(
          'Hayabusa backend is not implemented yet.'
        );


        finish();

        return;
      }


      jobId =
        res.job_id;


      /*
       * Start both independent polling loops.
       */
      pollStatus();

      pollLogs(false);

    })

    .catch(function (err) {

      fail(
        'Could not start the job: ' +
        err.message
      );


      finish();

    });

}


/* ------------------------------------------------------------
   Build pipeline stage DOM
   ------------------------------------------------------------ */

const SVG_NS =
  'http://www.w3.org/2000/svg';


function buildStageElement(
  stage
) {

  const div =
    document.createElement(
      'div'
    );


  div.className =
    'pipe-stage';


  div.id =
    stageId(
      stage.id
    );


  const line =
    document.createElement(
      'div'
    );


  line.className =
    'pipe-line';


  const lineFill =
    document.createElement(
      'div'
    );


  lineFill.className =
    'pipe-line-fill';


  lineFill.id =
    fillId(
      stage.id
    );


  line.appendChild(
    lineFill
  );


  const node =
    document.createElement(
      'div'
    );


  node.className =
    'pipe-node';


  const svg =
    document.createElementNS(
      SVG_NS,
      'svg'
    );


  svg.setAttribute(
    'viewBox',
    '0 0 24 24'
  );


  const use =
    document.createElementNS(
      SVG_NS,
      'use'
    );


  use.setAttribute(
    'href',
    '#i-check'
  );


  svg.appendChild(
    use
  );


  node.appendChild(
    svg
  );


  const title =
    document.createElement(
      'div'
    );


  title.className =
    'pipe-title';


  title.textContent =
    stage.title;


  const sub =
    document.createElement(
      'div'
    );


  sub.className =
    'pipe-sub';


  sub.id =
    subId(
      stage.id
    );


  div.append(
    line,
    node,
    title,
    sub
  );


  return div;
}