/* ============================================================
   login.js — DFIR-AI frontend
   Fake login for now — see note in initLogin(). Do not add real
   authentication here until the backend exposes POST /api/login;
   swapping this for a real call later only means replacing the
   body of the submit handler below with a fetch() + token check.
   ============================================================ */

function initLogin() {
  const form = $('loginForm');
  if (!form) return;

  form.addEventListener('submit', function (e) {
    e.preventDefault();

    const loginError = $('loginError');
    if (loginError) loginError.style.display = 'none';

    $('page-login').classList.remove('active');
    $('app').style.display = 'block';

    Router.go('home');
  });

  const logoutBtn = $('btnLogout');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);
}

function logout() {
  const app = $('app');
  const loginPage = $('page-login');
  if (app) app.style.display = 'none';
  if (loginPage) loginPage.classList.add('active');

  const u = $('username');
  const p = $('password');
  if (u) u.value = '';
  if (p) p.value = '';
}
