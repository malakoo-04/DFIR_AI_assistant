/* ============================================================
   results.js — DFIR-AI frontend
   Investigation results page.

   REAL ARTIFACTS
   ------------------------------------------------------------
   DFIR:
     final_report -> generated DFIR report

   IOC:
     ioc_report -> JSON

   Hayabusa:
     hayabusa_report -> CSV
     hayabusa_html_report -> HTML summary

   IMPORTANT:
   Runtime statistics come from state.jobStats, which is populated
   from the real backend job status.

   No Hayabusa numbers are hardcoded here.
   ============================================================ */

const CARD_ARTIFACT_KEY = {
  cardDfir: 'final_report_pdf',
  cardIoc: 'ioc_report',
  cardHaya: 'hayabusa_report',
};


/* ============================================================
   Artifact helpers
   ============================================================ */

function artifactKeyForButton(btn) {

  if (btn.dataset.artifact) {
    return btn.dataset.artifact;
  }

  const card =
    btn.closest('.result-card');

  return card
    ? CARD_ARTIFACT_KEY[card.id]
    : null;
}


function hasRealFile(key) {

  return !!(
    key &&
    state.jobId &&
    state.resultPaths &&
    state.resultPaths[key]
  );

}


/* ============================================================
   Results-page cleanup
   ============================================================ */

function hideUnusedResultCards() {

  const timeline =
    $('cardTimeline');

  if (timeline) {
    timeline.style.display = 'none';
  }

  const mitre =
    $('cardMitre');

  if (mitre) {
    mitre.style.display = 'none';
  }

}


/* ============================================================
   IOC helpers
   ============================================================ */

function extractIocEntries(data) {

  if (!data) {
    return [];
  }

  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data.iocs)) {
    return data.iocs;
  }

  if (Array.isArray(data.IOCs)) {
    return data.IOCs;
  }

  if (Array.isArray(data.indicators)) {
    return data.indicators;
  }

  if (Array.isArray(data.INDICATORS)) {
    return data.INDICATORS;
  }

  if (Array.isArray(data.results)) {
    return data.results;
  }

  if (
    data.data &&
    Array.isArray(data.data)
  ) {
    return data.data;
  }

  if (
    data.data &&
    Array.isArray(data.data.iocs)
  ) {
    return data.data.iocs;
  }

  return [];
}


function getIocDisplayValue(ioc) {

  if (
    ioc === null ||
    ioc === undefined
  ) {
    return '—';
  }

  if (
    typeof ioc === 'string' ||
    typeof ioc === 'number'
  ) {
    return String(ioc);
  }

  return (
    ioc.value ??
    ioc.indicator ??
    ioc.ioc ??
    ioc.observable ??
    ioc.content ??
    ioc.hash ??
    ioc.ip ??
    ioc.domain ??
    ioc.url ??
    '—'
  );
}


function getIocType(ioc) {

  if (
    !ioc ||
    typeof ioc !== 'object'
  ) {
    return 'INDICATOR';
  }

  return String(
    ioc.type ??
    ioc.ioc_type ??
    ioc.indicator_type ??
    ioc.kind ??
    'INDICATOR'
  ).toUpperCase();
}


function getIocConfidence(ioc) {

  if (
    !ioc ||
    typeof ioc !== 'object'
  ) {
    return '';
  }

  const value =
    ioc.confidence ??
    ioc.confidence_level ??
    ioc.score ??
    '';

  return (
    value === null ||
    value === undefined
  )
    ? ''
    : String(value);
}


/* ============================================================
   IOC preview modal
   ============================================================ */

function ensureIocPreviewModal() {

  let modal =
    document.getElementById(
      'iocPreviewModal'
    );

  if (modal) {
    return modal;
  }

  modal =
    document.createElement('div');

  modal.id =
    'iocPreviewModal';

  modal.style.cssText = [
    'position:fixed',
    'inset:0',
    'z-index:9999',
    'display:none',
    'align-items:center',
    'justify-content:center',
    'padding:24px',
    'background:rgba(0,0,0,.72)',
    'backdrop-filter:blur(4px)'
  ].join(';');

  modal.innerHTML = `
    <div style="
      width:min(720px, 100%);
      max-height:80vh;
      overflow:auto;
      background:var(--bg-card, #111722);
      border:1px solid var(--border, #263044);
      border-radius:16px;
      box-shadow:0 24px 80px rgba(0,0,0,.5);
      padding:24px;
    ">

      <div style="
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:16px;
        margin-bottom:8px;
      ">

        <div>

          <h2 style="margin:0;">
            IOC preview
          </h2>

          <p
            id="iocPreviewSubtitle"
            style="
              margin:6px 0 0;
              color:var(--text-muted, #8994a8);
            "
          ></p>

        </div>

        <button
          id="iocPreviewClose"
          type="button"
          class="icon-btn"
          title="Close"
          aria-label="Close IOC preview"
        >×</button>

      </div>

      <div id="iocPreviewBody"></div>

      <div style="
        display:flex;
        justify-content:flex-end;
        margin-top:20px;
      ">

        <button
          id="iocPreviewFullJson"
          type="button"
          class="btn btn-secondary"
        >
          Open full JSON
        </button>

      </div>

    </div>
  `;

  document.body.appendChild(modal);

  document
    .getElementById(
      'iocPreviewClose'
    )
    .addEventListener(
      'click',
      closeIocPreview
    );

  modal.addEventListener(
    'click',
    function (event) {

      if (
        event.target === modal
      ) {
        closeIocPreview();
      }

    }
  );

  document
    .getElementById(
      'iocPreviewFullJson'
    )
    .addEventListener(
      'click',
      function () {

        if (
          hasRealFile(
            'ioc_report'
          )
        ) {

          window.open(
            API_BASE +
              '/api/file/' +
              state.jobId +
              '/ioc_report',
            '_blank'
          );

        }

      }
    );

  return modal;
}


function closeIocPreview() {

  const modal =
    document.getElementById(
      'iocPreviewModal'
    );

  if (modal) {
    modal.style.display = 'none';
  }

}


function openIocPreview() {

  if (
    !hasRealFile(
      'ioc_report'
    )
  ) {
    return;
  }

  const modal =
    ensureIocPreviewModal();

  const body =
    document.getElementById(
      'iocPreviewBody'
    );

  const subtitle =
    document.getElementById(
      'iocPreviewSubtitle'
    );

  body.innerHTML = `
    <div style="
      padding:24px;
      text-align:center;
      color:var(--text-muted, #8994a8);
    ">
      Loading IOC data…
    </div>
  `;

  modal.style.display = 'flex';

  fetch(
    API_BASE +
      '/api/file/' +
      state.jobId +
      '/ioc_report'
  )
    .then(function (res) {

      if (!res.ok) {
        throw new Error(
          'HTTP ' + res.status
        );
      }

      return res.json();

    })

    .then(function (data) {

      const entries =
        extractIocEntries(data);

      const firstThree =
        entries.slice(0, 3);

      subtitle.textContent =
        'Showing ' +
        firstThree.length +
        ' of ' +
        entries.length +
        ' indicators';

      if (
        !firstThree.length
      ) {

        body.innerHTML = `
          <div style="
            padding:24px;
            border:1px solid var(--border, #263044);
            border-radius:12px;
            color:var(--text-muted, #8994a8);
          ">
            No IOC entries were found
            in the generated report.
          </div>
        `;

        return;
      }

      body.innerHTML = '';

      firstThree.forEach(
        function (ioc, index) {

          const card =
            document.createElement(
              'div'
            );

          card.style.cssText = [
            'padding:16px',
            'margin-top:12px',
            'border:1px solid var(--border, #263044)',
            'border-radius:12px',
            'background:rgba(255,255,255,.02)'
          ].join(';');

          const type =
            getIocType(ioc);

          const value =
            getIocDisplayValue(ioc);

          const confidence =
            getIocConfidence(ioc);

          card.innerHTML = `
            <div style="
              display:flex;
              align-items:center;
              justify-content:space-between;
              gap:12px;
              margin-bottom:8px;
            ">

              <span style="
                font-family:monospace;
                font-size:.8rem;
                color:var(--text-muted, #8994a8);
              ">
                IOC ${String(
                  index + 1
                ).padStart(2, '0')}
              </span>

              <span style="
                font-family:monospace;
                font-size:.8rem;
                color:var(--accent, #5b8cff);
              ">
                ${escapeHtml(type)}
              </span>

            </div>

            <div style="
              font-family:monospace;
              word-break:break-word;
              color:var(--text-primary, #f2f4f8);
            ">
              ${escapeHtml(
                String(value)
              )}
            </div>

            ${
              confidence
                ? `
                  <div style="
                    margin-top:8px;
                    font-size:.8rem;
                    color:var(--text-muted, #8994a8);
                  ">
                    Confidence:
                    ${escapeHtml(
                      confidence
                    )}
                  </div>
                `
                : ''
            }

          `;

          body.appendChild(card);

        }
      );

    })

    .catch(function (err) {

      subtitle.textContent = '';

      body.innerHTML = `
        <div style="
          padding:16px;
          border:1px solid rgba(255,80,80,.35);
          border-radius:12px;
          color:#ff8b8b;
        ">
          Could not load the IOC report:
          ${escapeHtml(
            err.message
          )}
        </div>
      `;

    });
}


function escapeHtml(value) {

  return String(value)
    .replace(
      /&/g,
      '&amp;'
    )
    .replace(
      /</g,
      '&lt;'
    )
    .replace(
      />/g,
      '&gt;'
    )
    .replace(
      /"/g,
      '&quot;'
    )
    .replace(
      /'/g,
      '&#039;'
    );

}


/* ============================================================
   Real downloads
   ============================================================ */

function realDownload(key) {

  if (
    !key ||
    !state.jobId
  ) {

    console.warn(
      '[Results] Missing job/artifact key:',
      key
    );

    return;
  }

  const url =
    API_BASE +
    '/api/file/' +
    state.jobId +
    '/' +
    key;

  const a =
    document.createElement(
      'a'
    );

  a.href = url;

  if (
    key === 'ioc_report'
  ) {

    a.download =
      'ioc_report.json';

  } else if (
    key === 'hayabusa_report'
  ) {

    a.download =
      'hayabusa_results.csv';

  } else if (
    key === 'hayabusa_html_report'
  ) {

    a.download =
      'hayabusa_report.html';

  } else if (
    key === 'final_report_pdf'
  ) {

    a.download =
      'final_report.pdf';

  } else {

    a.download =
      'final_report.pdf';

  }

  document.body.appendChild(a);

  a.click();

  document.body.removeChild(a);

}


/* ============================================================
   Hayabusa runtime statistics
   ============================================================ */

function getHayabusaStats() {

  return state.jobStats || {};

}


function setHayabusaMetaValue(
  elementId,
  value
) {

  const element =
    $(elementId);

  if (!element) {
    return;
  }

  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {

    element.textContent =
      '—';

    return;
  }

  element.textContent =
    Number(value).toLocaleString();

}


function renderHayabusaStats() {

  const stats =
    getHayabusaStats();

  setHayabusaMetaValue(
    'metaHayaCount',
    stats.detections
  );

  setHayabusaMetaValue(
    'metaHayaCritical',
    stats.critical
  );

  setHayabusaMetaValue(
    'metaHayaChannels',
    stats.channels
  );

}


/* ============================================================
   DFIR runtime statistics
   ============================================================ */

function renderDfirStats() {

  const stats =
    state.jobStats || {};

  /*
   * Accept the real backend field names if present.
   * No values are invented.
   */

  const pages =
    stats.pages ??
    stats.report_pages ??
    stats.final_report_pages;

  const incidents =
    stats.incidents ??
    stats.incident_count ??
    stats.generated_incidents ??
    stats.incidents_generated;

  const pagesElement =
    $('metaDfirPages');

  const incidentsElement =
    $('metaDfirIncidents');

  if (pagesElement) {

    pagesElement.textContent =
      pages === null ||
      pages === undefined ||
      pages === ''
        ? '—'
        : Number(pages).toLocaleString();

  }

  if (incidentsElement) {

    incidentsElement.textContent =
      incidents === null ||
      incidents === undefined ||
      incidents === ''
        ? '—'
        : Number(incidents).toLocaleString();

  }

}


/* ============================================================
   Initialization
   ============================================================ */

function initResults() {

  hideUnusedResultCards();

  renderHayabusaStats();

  renderDfirStats();


  /*
   * Real artifact downloads only.
   */
  document
    .querySelectorAll(
      '[data-download]'
    )
    .forEach(
      function (btn) {

        const key =
          artifactKeyForButton(
            btn
          );

        /*
         * Hayabusa produces CSV, never JSON.
         */
        if (
          key ===
            'hayabusa_report' &&
          /json/i.test(
            btn.textContent || ''
          )
        ) {

          btn.style.display =
            'none';

          return;
        }

        btn.addEventListener(
          'click',
          function () {

            if (
              hasRealFile(key)
            ) {

              realDownload(key);

              return;
            }

            console.warn(
              '[Results] No real artifact available:',
              key
            );

          }
        );

      }
    );


  /*
   * Explicit artifact buttons.
   *
   * Hayabusa exposes two real files from one card:
   *   - official HTML Results Summary
   *   - complete CSV detection timeline
   */
  document
    .querySelectorAll(
      '.rc-actions [data-artifact]'
    )
    .forEach(
      function (btn) {

        btn.addEventListener(
          'click',
          function () {

            const key =
              artifactKeyForButton(
                btn
              );

            if (
              !hasRealFile(key)
            ) {

              console.warn(
                '[Results] No real artifact available:',
                key
              );

              return;
            }

            if (
              key ===
              'hayabusa_html_report'
            ) {

              window.open(
                API_BASE +
                  '/api/file/' +
                  state.jobId +
                  '/' +
                  key,
                '_blank'
              );

            } else {

              realDownload(key);

            }

          }
        );

      }
    );


  /*
   * Preview buttons.
   *
   * IOC:
   *   Show first three IOCs.
   *
   * DFIR:
   *   Open the real generated PDF.
   *
   * Hayabusa:
   *   Open the real HTML report or CSV.
   */
  document
    .querySelectorAll(
      '.rc-actions .btn:not([data-artifact])'
    )
    .forEach(
      function (btn) {

        const use =
          btn.querySelector(
            'svg use'
          );

        if (
          !use ||
          use.getAttribute(
            'href'
          ) !== '#i-eye'
        ) {

          return;
        }

        btn.addEventListener(
          'click',
          function () {

            const key =
              artifactKeyForButton(
                btn
              );


            /*
             * IOC preview.
             */
            if (
              key ===
              'ioc_report'
            ) {

              openIocPreview();

              return;
            }


            /*
             * DFIR report / Hayabusa files.
             */
            if (
              (
                key ===
                  'final_report_pdf' ||
                key ===
                  'hayabusa_report' ||
                key ===
                  'hayabusa_html_report'
              ) &&
              hasRealFile(key)
            ) {

              window.open(
                API_BASE +
                  '/api/file/' +
                  state.jobId +
                  '/' +
                  key,
                '_blank'
              );

            }

          }
        );

      }
    );

}


/* ============================================================
   Result population
   ============================================================ */

function prepareResults(
  pipeline
) {

  $('resTitle').textContent =
    state.invName;

  $('resSubtitle').textContent =
    pipeline.label +
    ' · case artifacts generated by the analysis pipeline.';

  $('resSummaryTitle').textContent =
    pipeline.resultTitle +
    ' ready';

  const secs =
    Math.floor(
      (
        Date.now() -
        state.startTime
      ) / 1000
    ) ||
    Math.round(
      pipeline.duration / 1000
    );

  const m =
    String(
      Math.floor(
        secs / 60
      )
    ).padStart(
      2,
      '0'
    );

  const s =
    String(
      secs % 60
    ).padStart(
      2,
      '0'
    );

  const analyst =
    $('invAnalyst')
      .value
      .trim() ||
    'a.moreau';

  $('resSummaryMeta').textContent =
    'Completed in ' +
    m +
    ':' +
    s +
    ' · ' +
    analyst;


  /* ----------------------------------------------------------
     Which artifacts were actually generated?
     ---------------------------------------------------------- */

  const byRun = {

    dfir: {
      dfir: true,
      ioc: true,
      haya: false
    },

    ioc: {
      dfir: false,
      ioc: true,
      haya: false
    },

    haya: {
      dfir: false,
      ioc: false,
      haya: true
    }

  };

  const generated =
    byRun[state.runType] ||
    byRun.dfir;


  setCardState(
    'cardDfir',
    'tagDfir',
    generated.dfir,
    'Generated'
  );

  setCardState(
    'cardIoc',
    'tagIoc',
    generated.ioc,
    'Generated'
  );

  setCardState(
    'cardHaya',
    'tagHaya',
    generated.haya,
    'Generated'
  );


  /* ----------------------------------------------------------
     IOC is JSON only
     ---------------------------------------------------------- */

  const iocCard =
    $('cardIoc');

  if (iocCard) {

    const formatLabels =
      iocCard.querySelectorAll(
        '.meta-value'
      );

    formatLabels.forEach(
      function (element) {

        if (
          /pdf/i.test(
            element.textContent
          )
        ) {

          element.textContent =
            'JSON';

        }

      }
    );

    iocCard
      .querySelectorAll(
        'button'
      )
      .forEach(
        function (btn) {

          if (
            /download\s*pdf/i.test(
              btn.textContent || ''
            )
          ) {

            btn.textContent =
              'Download JSON';

          }

        }
      );

  }


  /* ----------------------------------------------------------
     IOC count
     ---------------------------------------------------------- */

  const iocCount =
    $('metaIocCount');

  if (iocCount) {
    iocCount.textContent =
      '—';
  }


  /* ----------------------------------------------------------
     Hayabusa real statistics
     ---------------------------------------------------------- */

  if (
    state.runType === 'haya'
  ) {

    renderHayabusaStats();

  }


  /* ----------------------------------------------------------
     DFIR real statistics
     ---------------------------------------------------------- */

  if (
    state.runType === 'dfir'
  ) {

    renderDfirStats();

  }


  /* ----------------------------------------------------------
     Real IOC statistics
     ---------------------------------------------------------- */

  if (
    generated.ioc &&
    hasRealFile(
      'ioc_report'
    )
  ) {

    loadRealIocStats();

  }

}


/* ============================================================
   Real IOC statistics
   ============================================================ */

async function loadRealIocStats() {

  try {

    const res =
      await fetch(
        API_BASE +
          '/api/file/' +
          state.jobId +
          '/ioc_report'
      );

    if (!res.ok) {

      throw new Error(
        'HTTP ' +
        res.status
      );

    }

    const data =
      await res.json();

    const entries =
      extractIocEntries(
        data
      );

    const iocCount =
      $('metaIocCount');

    if (iocCount) {

      iocCount.textContent =
        entries.length.toLocaleString();

    }


    let highConfidence =
      0;

    let confidenceSeen =
      false;


    entries.forEach(
      function (ioc) {

        const confidence =
          getIocConfidence(
            ioc
          );

        if (!confidence) {
          return;
        }

        confidenceSeen =
          true;

        const normalized =
          confidence.toLowerCase();

        if (
          normalized === 'high' ||
          normalized === 'high-confidence' ||
          normalized === 'high_confidence' ||
          normalized === '0.9' ||
          normalized === '1'
        ) {

          highConfidence++;

        }

      }
    );


    const highConfElement =
      $('cardIoc')?.querySelector(
        '.result-meta .meta-item:nth-child(2) .meta-value'
      );


    if (
      highConfElement
    ) {

      highConfElement.textContent =
        confidenceSeen
          ? highConfidence.toLocaleString()
          : '—';

    }

  } catch (err) {

    console.warn(
      '[Results] Could not load IOC statistics:',
      err
    );

    const iocCount =
      $('metaIocCount');

    if (iocCount) {
      iocCount.textContent =
        '—';
    }

  }

}


/* ============================================================
   Card state
   ============================================================ */

function setCardState(
  cardId,
  tagId,
  isGenerated,
  generatedLabel
) {

  const card =
    $(cardId);

  const tag =
    $(tagId);

  if (
    !card ||
    !tag
  ) {
    return;
  }


  if (isGenerated) {

    card.classList.remove(
      'disabled'
    );

    tag.textContent =
      generatedLabel;

    tag.classList.remove(
      'not-run'
    );

    card
      .querySelectorAll(
        'button'
      )
      .forEach(
        function (b) {

          b.disabled =
            false;

        }
      );

  } else {

    card.classList.add(
      'disabled'
    );

    tag.textContent =
      'Not run this session';

    tag.classList.add(
      'not-run'
    );

    card
      .querySelectorAll(
        '.rc-actions button'
      )
      .forEach(
        function (b) {

          b.disabled =
            true;

        }
      );

  }

}