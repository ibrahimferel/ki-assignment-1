(() => {
  const form = document.getElementById('register-form');
  const submit = form.querySelector('button[type="submit"]');
  const status = form.querySelector('.submit-status');
  const label = form.querySelector('.submit-label');
  document.querySelectorAll('[data-password-target]').forEach((button) => {
    const input = document.getElementById(button.dataset.passwordTarget);
    button.hidden = false;
    button.addEventListener('click', () => {
      const visible = input.type === 'password';
      input.type = visible ? 'text' : 'password';
      button.textContent = visible ? 'Hide' : 'Show';
      button.setAttribute('aria-pressed', String(visible));
      button.setAttribute('aria-label', `${visible ? 'Hide' : 'Show'} ${input.id === 'confirm' ? 'repeated password' : 'password'}`);
    });
  });
  form.addEventListener('submit', () => {
    submit.disabled = true;
    label.textContent = 'Creating account…';
    status.textContent = 'Creating your account. Please wait.';
  });
  window.addEventListener('pageshow', () => {
    submit.disabled = false;
    label.textContent = 'Create account';
    status.textContent = '';
  });
})();
