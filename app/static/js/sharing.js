(() => {
  'use strict';

  // ------------------------------------------------------------------ setup
  const root = document.getElementById('sharing');
  const requestsUrl = root.dataset.requestsUrl;   // /sharing/requests
  const recordsUrl = root.dataset.recordsUrl;     // /storage/
  const loginUrl = root.dataset.loginUrl;
  const $ = (id) => document.getElementById(id);

  const banner = $('sharing-message');
  const requestForm = $('request-form');
  const requestSubmit = $('request-submit');
  const requestStatus = $('request-status');
  const usernameInput = $('request-username');
  const reasonInput = $('request-reason');
  const incomingList = $('incoming-list');
  const outgoingList = $('outgoing-list');
  const incomingStatus = $('incoming-status');
  const outgoingStatus = $('outgoing-status');
  const approveDialog = $('approve-dialog');
  const packageDialog = $('package-dialog');
  const unlockDialog = $('unlock-dialog');
  const revokeDialog = $('revoke-dialog');
  const sharedPanel = $('shared-panel');
  const sharedFiles = $('shared-files');

  const USERNAME_RULE = /^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$/;
  const MAX_REASON = 500;
  const MAX_PACKAGE = 2048;
  const MAX_APPROVE_FILES = 100;
  const KIND_LABELS = {
    id_card: 'Identity scan', document: 'Medical document',
    video: 'Symptom video', personal_data: 'Personal data',
  };
  const PREVIEW_TYPES = new Set(['image/jpeg', 'image/png']);

  // In-memory state only. Nothing here is written to localStorage,
  // sessionStorage, cookies or the URL.
  let incoming = [];
  let outgoing = [];
  let loadCounter = 0;
  let shared = null;            // the open shared-files view, or null
  let sharedTimer = null;
  const unlockLockedUntil = new Map(); // request id -> timestamp (429 lock)
  let unlockLockTimer = null;

  // ---------------------------------------------------------------- helpers
  function csrfToken() {
    const input = document.querySelector('input[name="csrf_token"]');
    return input ? input.value : '';
  }

  function say(text, isError = false) {
    banner.textContent = text;
    banner.hidden = !text;
    banner.classList.toggle('error-notice', isError);
  }

  function formatSize(bytes) {
    if (!Number.isFinite(bytes)) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
  }

  // Dates arrive as UTC ISO 8601 ending in "Z", maybe with microseconds.
  // Browsers only reliably read three fraction digits, so cut the rest.
  function parseDate(value) {
    if (!value) return null;
    const time = Date.parse(String(value).replace(/(\.\d{3})\d+(?=Z$)/, '$1'));
    return Number.isNaN(time) ? null : time;
  }

  function formatDate(value) {
    const time = parseDate(value);
    if (time === null) return '-';
    return new Date(time).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function formatCountdown(ms) {
    const total = Math.max(0, Math.ceil(ms / 1000));
    const minutes = Math.floor(total / 60);
    return `${minutes}:${String(total % 60).padStart(2, '0')}`;
  }

  function isExpired(entry) {
    const end = parseDate(entry.expires_at);
    return entry.status === 'approved' && end !== null && end <= Date.now();
  }

  function isActive(entry) {
    return entry.status === 'approved' && !isExpired(entry);
  }

  function statusLabel(entry) {
    if (isExpired(entry)) return 'expired';
    return entry.status;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // ------------------------------------------------------------ API wrapper
  class ApiError extends Error {
    constructor(message, status, retryAfter = 0) {
      super(message);
      this.status = status;
      this.retryAfter = retryAfter;
    }
  }

  // Sends one request. Never retries. Returns parsed JSON, or null for 204.
  // `messages` overrides the default text for a status code.
  async function api(url, { method = 'GET', body, messages = {} } = {}) {
    const options = { method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') options.headers['X-CSRFToken'] = csrfToken();
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(url, options);
    } catch (_) {
      throw new ApiError('Connection failed. Check your connection, then refresh the list before trying again.', 0);
    }
    // A login redirect is followed by fetch and ends as login HTML with 200.
    if (response.redirected || response.status === 401) {
      say('Your session has expired. Taking you to the login page...', true);
      window.setTimeout(() => window.location.assign(loginUrl), 800);
      throw new ApiError('Your session has expired. Log in again to continue.', 401);
    }
    if (response.status === 204) return null;
    const isJson = (response.headers.get('content-type') || '').includes('application/json');
    if (!response.ok) {
      const retryAfter = Number.parseInt(response.headers.get('Retry-After') || '', 10) || 0;
      throw new ApiError(describe(response.status, isJson, retryAfter, messages), response.status, retryAfter);
    }
    if (!isJson) throw new ApiError('The server sent an unexpected response. Refresh the page and try again.', response.status);
    try {
      return await response.json();
    } catch (_) {
      throw new ApiError('The server sent an unreadable response. Refresh the page and try again.', response.status);
    }
  }

  function describe(status, isJson, retryAfter, messages) {
    // HTML bodies on 400 are CSRF failures, not validation errors.
    if (status === 400 && !isJson) return 'This page has expired. Reload the page and try again.';
    if (messages[status]) return messages[status];
    switch (status) {
      case 400: return 'The request could not be accepted. Refresh the list and try again.';
      case 404: return 'Not found. It may have expired or been removed. Refresh the list.';
      case 413: return 'The request is too large.';
      case 422: return 'The data could not be processed.';
      case 429: return `Too many attempts. Try again in ${retryAfter || 'a few'} seconds.`;
      default: return `Something went wrong on the server (${status}). Refresh the list before trying again.`;
    }
  }

  // Disables a button while a task runs. Re-enables it afterwards, because the
  // button may have survived a list refresh.
  async function busy(button, task) {
    if (button.disabled) return;
    button.disabled = true;
    try {
      return await task();
    } finally {
      button.disabled = false;
    }
  }

  function requestUrl(id, suffix = '') {
    return `${requestsUrl}/${id}${suffix}`;
  }

  // ----------------------------------------------------------- request list
  function makeButton(label, action, className = 'subtle-button') {
    const button = el('button', className, label);
    button.type = 'button';
    button.addEventListener('click', () => action(button));
    return button;
  }

  function renderEntry(entry, role) {
    const item = el('li', 'record-item request-item');
    const meta = el('div', 'record-meta');
    const top = el('div', 'request-top');
    top.append(el('strong', '', entry.username), el('span', `badge badge-${statusLabel(entry)}`, statusLabel(entry)));
    meta.append(top, el('small', 'request-reason', `Reason: ${entry.reason}`));
    const dates = [`Requested ${formatDate(entry.created_at)}`];
    if (entry.decided_at) dates.push(`Decided ${formatDate(entry.decided_at)}`);
    if (entry.expires_at) dates.push(`${isExpired(entry) ? 'Expired' : 'Expires'} ${formatDate(entry.expires_at)}`);
    meta.append(el('small', '', dates.join(' · ')));

    const actions = el('div', 'record-actions');
    if (role === 'incoming') {
      if (entry.status === 'pending') {
        actions.append(
          makeButton('Approve', () => openApprove(entry), 'primary button small'),
          makeButton('Reject', (button) => rejectRequest(entry, button)),
        );
      } else if (isActive(entry)) {
        actions.append(
          makeButton('Show key package', (button) => showKeyPackage(entry, button)),
          makeButton('Revoke', () => openRevoke(entry), 'danger-button'),
        );
      }
    } else if (isActive(entry)) {
      actions.append(makeButton('Unlock', () => openUnlock(entry), 'primary button small'));
    }
    item.append(meta, actions);
    return item;
  }

  function renderList(list, statusEl, entries, role, emptyText) {
    list.replaceChildren(...entries.map((entry) => renderEntry(entry, role)));
    statusEl.textContent = entries.length
      ? `${entries.length} ${entries.length === 1 ? 'request' : 'requests'}`
      : emptyText;
  }

  function renderRequests() {
    renderList(incomingList, incomingStatus, incoming, 'incoming', 'No one has asked for access to your records yet.');
    renderList(outgoingList, outgoingStatus, outgoing, 'outgoing', 'You have not requested access to anyone yet.');
  }

  async function loadRequests() {
    const ticket = ++loadCounter;
    incomingStatus.textContent = 'Loading requests...';
    outgoingStatus.textContent = 'Loading requests...';
    try {
      const data = await api(requestsUrl);
      if (ticket !== loadCounter) return; // a newer load replaced this one
      incoming = Array.isArray(data.incoming) ? data.incoming : [];
      outgoing = Array.isArray(data.outgoing) ? data.outgoing : [];
      renderRequests();
      checkSharedStillValid();
    } catch (error) {
      if (ticket !== loadCounter) return;
      const text = `Could not load requests. ${error.message}`;
      incomingStatus.textContent = text;
      outgoingStatus.textContent = text;
    }
  }

  // ----------------------------------------------------------- request form
  function checkRequestForm() {
    const username = usernameInput.value.trim().toLowerCase();
    const reason = reasonInput.value.trim();
    if (!USERNAME_RULE.test(username)) {
      return { error: 'Enter a username of 3 to 32 characters: letters, digits, dot, underscore or hyphen, starting and ending with a letter or digit.' };
    }
    if (!reason) return { error: 'Enter a reason for your request.' };
    if (reason.length > MAX_REASON) return { error: `The reason must be at most ${MAX_REASON} characters.` };
    return { username, reason };
  }

  reasonInput.addEventListener('input', () => {
    $('request-reason-count').textContent = String(reasonInput.value.length);
  });

  requestForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const checked = checkRequestForm();
    if (checked.error) {
      requestStatus.textContent = checked.error;
      requestStatus.classList.add('field-error');
      return;
    }
    requestStatus.classList.remove('field-error');
    requestStatus.textContent = 'Sending...';
    await busy(requestSubmit, async () => {
      try {
        await api(requestsUrl, {
          method: 'POST',
          body: { username: checked.username, reason: checked.reason },
          messages: {
            400: 'This request cannot be sent. You cannot ask yourself, and you can only have one pending request to the same person.',
            404: 'No user with that username was found.',
          },
        });
        requestStatus.textContent = `Request sent to ${checked.username}. They will see it under Incoming.`;
        requestForm.reset();
        $('request-reason-count').textContent = '0';
        await loadRequests();
      } catch (error) {
        requestStatus.classList.add('field-error');
        requestStatus.textContent = error.message;
      }
    });
  });

  // ------------------------------------------------------------ owner: reject
  async function rejectRequest(entry, button) {
    await busy(button, async () => {
      try {
        await api(requestUrl(entry.id, '/reject'), { method: 'POST' });
        say(`Request from ${entry.username} rejected.`);
      } catch (error) {
        say(error.message, true);
      }
      await loadRequests(); // refresh even after a failure: the state may have changed
    });
  }

  // ------------------------------------------------------------ owner: approve
  let approveTarget = null;

  function setApproveError(text) {
    $('approve-error').textContent = text;
  }

  async function openApprove(entry) {
    approveTarget = entry;
    $('approve-title').textContent = `Approve request from ${entry.username}`;
    $('approve-intro').textContent = `Reason: ${entry.reason}`;
    $('approve-status').textContent = 'Loading your records...';
    $('approve-status').hidden = false;
    $('approve-picker').hidden = true;
    $('approve-list').replaceChildren();
    $('approve-submit').disabled = true;
    setApproveError('');
    approveDialog.showModal();
    try {
      const data = await api(recordsUrl);
      const items = Array.isArray(data.items) ? data.items : [];
      if (!items.length) {
        $('approve-status').textContent = 'You have no records to share. Add records to your vault first, then approve this request.';
        return;
      }
      items.forEach((item) => {
        const row = el('li', 'check-row');
        const box = el('input');
        box.type = 'checkbox';
        box.checked = true;
        box.id = `approve-file-${item.id}`;
        box.value = String(item.id);
        const label = el('label');
        label.htmlFor = box.id;
        const name = item.kind === 'personal_data' ? `Personal record #${item.id}` : item.name;
        label.append(el('strong', '', name), el('small', '', `${KIND_LABELS[item.kind] || 'Record'} · ${formatSize(item.size)}`));
        row.append(box, label);
        $('approve-list').append(row);
      });
      $('approve-status').hidden = true;
      $('approve-picker').hidden = false;
      $('approve-submit').disabled = false;
    } catch (error) {
      $('approve-status').textContent = `Could not load your records. ${error.message}`;
    }
  }

  $('approve-cancel').addEventListener('click', () => approveDialog.close());

  $('approve-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const ids = [...$('approve-list').querySelectorAll('input:checked')].map((box) => Number(box.value));
    if (!ids.length) {
      setApproveError('Select at least one record to share.');
      return;
    }
    if (ids.length > MAX_APPROVE_FILES) {
      setApproveError(`You can share at most ${MAX_APPROVE_FILES} records at a time.`);
      return;
    }
    setApproveError('');
    const target = approveTarget;
    await busy($('approve-submit'), async () => {
      try {
        const data = await api(requestUrl(target.id, '/approve'), {
          method: 'POST',
          body: { file_ids: ids },
          messages: { 400: 'This request cannot be approved. It may already have been decided, or a selected record is no longer available.' },
        });
        approveDialog.close();
        say(`Request from ${target.username} approved. Send the key package to them now.`);
        showPackage(data.key_package, target);
        await loadRequests();
      } catch (error) {
        setApproveError(error.message);
        if (error.status === 400 || error.status === 404) loadRequests();
      }
    });
  });

  // -------------------------------------------------------- owner: key package
  function showPackage(text, entry) {
    $('package-title').textContent = `Key package for ${entry.username}`;
    $('package-text').value = text || '';
    $('package-status').textContent = '';
    packageDialog.showModal();
    $('package-text').focus();
    $('package-text').select();
    $('package-text').scrollTop = 0; // select() scrolls to the end; start at the top
  }

  async function showKeyPackage(entry, button) {
    await busy(button, async () => {
      try {
        const data = await api(requestUrl(entry.id, '/key-package'), {
          messages: { 404: 'The key package is no longer available. The share may have expired or been revoked.' },
        });
        showPackage(data.key_package, entry);
      } catch (error) {
        say(error.message, true);
        if (error.status === 404) await loadRequests();
      }
    });
  }

  $('package-copy').addEventListener('click', async () => {
    const field = $('package-text');
    const status = $('package-status');
    try {
      await navigator.clipboard.writeText(field.value);
      status.textContent = 'Copied. Paste it into WhatsApp or an email.';
    } catch (_) {
      field.focus();
      field.select();
      let copied = false;
      try { copied = document.execCommand('copy'); } catch (__) { copied = false; }
      status.textContent = copied
        ? 'Copied. Paste it into WhatsApp or an email.'
        : 'Copy failed. The text is selected: press Ctrl+C (or Cmd+C) to copy it.';
    }
  });

  $('package-download').addEventListener('click', () => {
    const blob = new Blob([$('package-text').value], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = el('a');
    link.href = url;
    link.download = 'medvault-key-package.txt';
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    $('package-status').textContent = 'Downloaded as medvault-key-package.txt.';
  });

  $('package-close').addEventListener('click', () => packageDialog.close());
  // The package is not kept in the page once the dialog is closed.
  packageDialog.addEventListener('close', () => {
    $('package-text').value = '';
    $('package-status').textContent = '';
  });

  // --------------------------------------------------------------- owner: revoke
  let revokeTarget = null;

  function openRevoke(entry) {
    revokeTarget = entry;
    $('revoke-description').textContent = `${entry.username} will lose access to the files you shared.`;
    $('revoke-error').textContent = '';
    revokeDialog.showModal();
  }

  $('revoke-cancel').addEventListener('click', () => revokeDialog.close());
  $('revoke-confirm').addEventListener('click', () => {
    const target = revokeTarget;
    return busy($('revoke-confirm'), async () => {
      try {
        await api(requestUrl(target.id, '/revoke'), {
          method: 'POST',
          messages: { 400: 'This share can no longer be revoked. It may already have been revoked or have expired.' },
        });
        revokeDialog.close();
        say(`Access for ${target.username} revoked.`);
      } catch (error) {
        $('revoke-error').textContent = error.message;
        if (error.status === 400 || error.status === 404) {
          // The state changed on the server; show the real state behind the dialog.
          await loadRequests();
          return;
        }
        return;
      }
      await loadRequests();
    });
  });

  // ------------------------------------------------------------ requester: unlock
  let unlockTarget = null;

  function setUnlockError(text) {
    $('unlock-error').textContent = text;
  }

  function updateUnlockLock() {
    window.clearInterval(unlockLockTimer);
    unlockLockTimer = null;
    const submit = $('unlock-submit');
    const until = unlockTarget ? unlockLockedUntil.get(unlockTarget.id) : null;
    if (!until || until <= Date.now()) {
      if (unlockTarget) unlockLockedUntil.delete(unlockTarget.id);
      submit.disabled = false;
      submit.textContent = 'Unlock';
      return;
    }
    const tick = () => {
      const left = until - Date.now();
      if (left <= 0) {
        window.clearInterval(unlockLockTimer);
        unlockLockTimer = null;
        if (unlockTarget) unlockLockedUntil.delete(unlockTarget.id);
        submit.disabled = false;
        submit.textContent = 'Unlock';
        setUnlockError('');
        return;
      }
      submit.disabled = true;
      submit.textContent = `Try again in ${Math.ceil(left / 1000)} s`;
    };
    tick();
    unlockLockTimer = window.setInterval(tick, 500);
  }

  function openUnlock(entry) {
    unlockTarget = entry;
    $('unlock-intro').textContent = `Paste the key package ${entry.username} sent you and type your own account password.`;
    $('unlock-package').value = '';
    $('unlock-password').value = '';
    $('unlock-file').value = '';
    setUnlockError('');
    updateUnlockLock();
    unlockDialog.showModal();
  }

  $('unlock-file').addEventListener('change', () => {
    const file = $('unlock-file').files[0];
    if (!file) return;
    if (file.size > 8192) {
      setUnlockError('That file is too large to be a key package.');
      $('unlock-file').value = '';
      return;
    }
    const reader = new FileReader();
    reader.addEventListener('load', () => {
      $('unlock-package').value = String(reader.result || '').trim();
      setUnlockError('');
    });
    reader.addEventListener('error', () => setUnlockError('The file could not be read.'));
    reader.readAsText(file);
  });

  $('unlock-cancel').addEventListener('click', () => unlockDialog.close());
  unlockDialog.addEventListener('close', () => {
    $('unlock-password').value = '';
    $('unlock-package').value = '';
    $('unlock-file').value = '';
    window.clearInterval(unlockLockTimer);
    unlockLockTimer = null;
    unlockTarget = null;
  });

  $('unlock-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const target = unlockTarget;
    const passwordField = $('unlock-password');
    const keyPackage = $('unlock-package').value;
    const password = passwordField.value;
    if (!keyPackage.trim()) { setUnlockError('Paste the key package you received.'); return; }
    if (keyPackage.length > MAX_PACKAGE) { setUnlockError('That text is too long to be a key package. Paste only the package.'); return; }
    if (!password) { setUnlockError('Enter your account password.'); return; }
    setUnlockError('');
    await busy($('unlock-submit'), async () => {
      try {
        const data = await api(requestUrl(target.id, '/unlock'), {
          method: 'POST',
          // The password is sent exactly as typed: not trimmed, not changed.
          body: { key_package: keyPackage, password },
          messages: {
            400: 'The key package or password was not accepted. Check both and try again.',
            404: 'These files are no longer available: the share may have expired or been revoked.',
            422: 'Could not unlock. Check the key package and your password.',
          },
        });
        unlockDialog.close();
        showShared(target, data);
        say(`Unlocked. You can now see the files ${target.username} shared with you.`);
      } catch (error) {
        setUnlockError(error.message);
        if (error.status === 429) {
          unlockLockedUntil.set(target.id, Date.now() + Math.max(1, error.retryAfter) * 1000);
          updateUnlockLock();
        }
        if (error.status === 404) { unlockDialog.close(); say(error.message, true); loadRequests(); }
      } finally {
        // Success or failure: the password never stays in the field.
        passwordField.value = '';
      }
    });
    // busy() re-enables the button; honour an active 429 lock again.
    updateUnlockLock();
  });

  // ------------------------------------------------------------ requester: files
  function fileUrl(requestId, fileId, action) {
    return requestUrl(requestId, `/files/${fileId}/${action}`);
  }

  function lockShared(reason) {
    window.clearInterval(sharedTimer);
    sharedTimer = null;
    shared = null;
    sharedFiles.replaceChildren(); // also removes the preview <img> elements
    sharedPanel.hidden = true;
    if (reason) say(reason, true);
  }

  function updateDeadlines() {
    if (!shared) return;
    const now = Date.now();
    if (shared.unlockedUntil !== null && shared.unlockedUntil <= now) {
      lockShared('The 15-minute unlock window ended. Unlock again with the key package and your password to keep viewing.');
      loadRequests();
      return;
    }
    if (shared.expiresAt !== null && shared.expiresAt <= now) {
      lockShared('This share has expired. Ask the owner to share again.');
      loadRequests();
      return;
    }
    $('shared-unlock').textContent = shared.unlockedUntil === null
      ? '-'
      : `${formatDate(new Date(shared.unlockedUntil).toISOString())} (${formatCountdown(shared.unlockedUntil - now)} left)`;
  }

  function checkSharedStillValid() {
    if (!shared) return;
    const entry = outgoing.find((candidate) => candidate.id === shared.requestId);
    if (!entry || !isActive(entry)) lockShared('Access to those files has ended. The share was revoked or has expired.');
  }

  function sharedProblem(error) {
    const status = $('shared-status');
    if (error.status === 404) {
      status.textContent = 'This file is no longer available. The unlock window may have ended or the share was revoked. Check your requests, and unlock again only if the share is still active.';
      loadRequests();
    } else {
      status.textContent = error.message;
    }
  }

  function renderSharedFile(file, requestId) {
    const item = el('li', 'record-item shared-item');
    const row = el('div', 'shared-row');
    const meta = el('div', 'record-meta');
    const title = file.kind === 'personal_data' ? `Personal record #${file.id}` : file.name;
    meta.append(el('strong', '', title), el('small', '', `${KIND_LABELS[file.kind] || 'Record'} · ${formatSize(file.size)}`));
    const actions = el('div', 'record-actions');

    if (file.kind === 'personal_data') {
      const detail = el('dl', 'view-fields shared-personal');
      detail.hidden = true;
      actions.append(makeButton('View details', (button) => showPersonal(file, requestId, detail, button)));
      row.append(meta, actions);
      item.append(row, detail);
      return item;
    }

    const link = el('a', 'record-download', 'Download');
    link.href = fileUrl(requestId, file.id, 'download');
    link.setAttribute('aria-label', `Download ${file.name}`);
    actions.append(link);
    row.append(meta, actions);
    item.append(row);

    if (PREVIEW_TYPES.has(file.content_type)) {
      const image = el('img', 'shared-preview');
      image.alt = `Preview of ${file.name}`;
      image.loading = 'lazy';
      image.addEventListener('error', () => {
        image.replaceWith(el('p', 'field-hint', 'The preview could not be loaded. If the unlock window ended, unlock again.'));
      });
      image.src = fileUrl(requestId, file.id, 'view');
      item.append(image);
    }
    return item;
  }

  async function showPersonal(file, requestId, detail, button) {
    await busy(button, async () => {
      try {
        const data = await api(fileUrl(requestId, file.id, 'personal'));
        const fields = [['Full name', 'nama'], ['NIK', 'nik'], ['Address', 'alamat'], ['Date of birth', 'tanggal_lahir']];
        detail.replaceChildren();
        fields.forEach(([label, key]) => {
          detail.append(el('dt', '', label), el('dd', '', data[key] === undefined ? '-' : String(data[key])));
        });
        detail.hidden = false;
        button.textContent = 'Refresh details';
        $('shared-status').textContent = '';
      } catch (error) {
        sharedProblem(error);
      }
    });
  }

  function showShared(entry, data) {
    window.clearInterval(sharedTimer);
    const files = Array.isArray(data.files) ? data.files : [];
    shared = {
      requestId: entry.id,
      expiresAt: parseDate(entry.expires_at),
      unlockedUntil: parseDate(data.unlocked_until),
    };
    $('shared-owner').textContent = `Shared by ${entry.username}. Only the records they approved are listed.`;
    $('shared-expires').textContent = formatDate(entry.expires_at);
    $('shared-status').textContent = files.length ? '' : 'No files were shared in this request.';
    sharedFiles.replaceChildren(...files.map((file) => renderSharedFile(file, entry.id)));
    sharedPanel.hidden = false;
    updateDeadlines();
    sharedTimer = window.setInterval(updateDeadlines, 1000);
    sharedPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('shared-hide').addEventListener('click', () => {
    lockShared('');
    say('Shared files hidden. Unlock again to view them while the share is active.');
  });

  // -------------------------------------------------------------------- start
  $('refresh-requests').addEventListener('click', (event) => busy(event.currentTarget, loadRequests));
  window.addEventListener('pageshow', (event) => {
    // After the back button the page may come from the cache: never keep a
    // password or package in a restored page.
    if (event.persisted) {
      $('unlock-password').value = '';
      loadRequests();
    }
  });
  loadRequests();
})();
