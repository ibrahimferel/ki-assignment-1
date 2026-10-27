(() => {
  const form = document.getElementById('login-form');
  const submit = form.querySelector('button[type="submit"]');
  const status = form.querySelector('.submit-status');
  const label = form.querySelector('.submit-label');
  const toggle = form.querySelector('[data-password-target]');
  const password = document.getElementById(toggle.dataset.passwordTarget);
  toggle.hidden = false;
  toggle.addEventListener('click', () => {
    const visible = password.type === 'password';
    password.type = visible ? 'text' : 'password';
    toggle.textContent = visible ? 'Hide' : 'Show';
    toggle.setAttribute('aria-pressed', String(visible));
    toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
  });
  form.addEventListener('submit', () => {
    submit.disabled = true;
    label.textContent = 'Logging in…';
    status.textContent = 'Logging in. Please wait.';
  });
  window.addEventListener('pageshow', () => {
    submit.disabled = false;
    label.textContent = 'Log in';
    status.textContent = '';
  });
})();
