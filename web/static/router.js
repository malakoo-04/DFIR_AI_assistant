/* ============================================================
   router.js — DFIR-AI frontend
   Single source of truth for the 5 pages. Screens are matched by
   id "page-<key>". Adding a page later only means adding one line
   here — nothing else has to change.

   Also owns the generic [data-nav="<page>"] click binding, so any
   element in the HTML (button, link, div) can trigger navigation
   declaratively instead of an inline onclick="" string. Elements
   whose target page changes at runtime (e.g. progCancelBtn) just
   get their data-nav attribute updated in place — the listener
   below reads node.dataset.nav fresh on every click, so no
   re-binding or .onclick reassignment is needed.
   Load order: this file must load before any file that calls
   Router.go(...) at click time (login.js, new_case.js, progress.js,
   results.js) and before app.js, which calls bindNavTriggers(). It
   also defines the global $() helper used by every other file.
   ============================================================ */

// Global shorthand used throughout the JS instead of repeating
// document.getElementById(...) everywhere.
function $(id) {
  return document.getElementById(id);
}

const Router = (function () {
  const PAGES = Object.freeze({
    home:     { screen: 'page-home',     crumb: 'Home' },
    new:      { screen: 'page-new',      crumb: 'New investigation' },
    progress: { screen: 'page-progress', crumb: 'Investigation progress' },
    results:  { screen: 'page-results',  crumb: 'Investigation results' },
  });

  let current = null;

  function el(id) {
    const node = $(id);
    if (!node) console.warn('[Router] missing element:', id);
    return node;
  }

  function renderCrumbs(key) {
    const crumbs = el('crumbs');
    if (!crumbs) return;

    if (key === 'home') {
      crumbs.innerHTML = '<span class="current">Home</span>';
      return;
    }

    crumbs.innerHTML =
      '<a href="#" data-nav="home" style="color:var(--text-tertiary)">Home</a>' +
      '<span class="sep">/</span>' +
      '<span class="current">' + PAGES[key].crumb + '</span>';

    // Dynamically-generated node — bind directly rather than relying
    // on the static bindNavTriggers() pass, which only runs once at
    // DOMContentLoaded and won't see nodes created after that.
    const homeLink = crumbs.querySelector('[data-nav="home"]');
    if (homeLink) {
      homeLink.addEventListener('click', function (e) {
        e.preventDefault();
        Router.go('home');
      });
    }
  }

  function go(key) {
    if (!PAGES[key]) {
      console.error('[Router] unknown page:', key);
      return;
    }

    document.querySelectorAll('.screen').forEach(function (s) {
      s.classList.remove('active');
    });

    const target = el(PAGES[key].screen);
    if (!target) return;

    target.classList.add('active');
    current = key;
    renderCrumbs(key);
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  function which() {
    return current;
  }

  // Binds every static [data-nav] element present at DOMContentLoaded
  // time. Called once from app.js. Elements added later (e.g. the
  // breadcrumb Home link) bind themselves in renderCrumbs() above.
  function bindNavTriggers() {
    document.querySelectorAll('[data-nav]').forEach(function (node) {
      node.addEventListener('click', function (e) {
        if (node.tagName === 'A') e.preventDefault();
        Router.go(node.dataset.nav);
      });
    });
  }

  return { go: go, which: which, bindNavTriggers: bindNavTriggers };
})();
