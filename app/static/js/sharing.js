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
  const sharedDialog = $('shared-dialog');
  const sharedFiles = $('shared-files');
  const requestDialog = $('request-dialog');

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
  // What the last successful unlock returned, per request id:
  // {files, unlockedUntil, expiresAt}. The server has no endpoint that lists
  // a share's files, so this is the only copy. It lives in memory only and is
  // dropped when the 15-minute unlock window ends, the share ends, or the page
  // is reloaded (then the requester unlocks again).
  const unlocked = new Map();
  let sharedOpen = null;        // id of the request whose files dialog is open
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

  // Each request reads as a short sentence: who, what happened, what to do next.
  function describeEntry(entry, role) {
    const name = entry.username;
    if (role === 'incoming') {
      if (entry.status === 'pending') return { before: '', after: ' asked to see your records', chip: 'Needs your decision', tone: 'amber' };
      if (isActive(entry)) return { before: 'You shared records with ', after: '', next: `Send ${name} the key package so they can unlock the files.` };
      if (entry.status === 'rejected') return { before: 'You declined ', after: '' };
      if (entry.status === 'revoked') return { before: 'You removed access for ', after: '' };
      return { before: '', after: "'s access ended" };
    }
    if (entry.status === 'pending') return { before: 'Waiting for ', after: ' to respond' };
    if (isActive(entry)) {
      const state = currentUnlock(entry.id);
      if (state) {
        return { before: '', after: ' approved your request', next: `Files are unlocked until ${formatDate(new Date(state.unlockedUntil).toISOString())}.` };
      }
      return { before: '', after: ' approved your request', next: `Ask ${name} for the key package, then unlock the files.`, chip: 'Ready to unlock', tone: 'teal' };
    }
    if (entry.status === 'rejected') return { before: '', after: ' declined your request' };
    if (entry.status === 'revoked') return { before: '', after: ' removed your access' };
    return { before: 'Your access to ', after: "'s records ended" };
  }

  function describeDates(entry) {
    const parts = [`Requested ${formatDate(entry.created_at)}`];
    if (entry.status === 'rejected' && entry.decided_at) parts.push(`Declined ${formatDate(entry.decided_at)}`);
    if (entry.status === 'revoked' && entry.decided_at) parts.push(`Removed ${formatDate(entry.decided_at)}`);
    if (entry.status === 'approved' && entry.expires_at) {
      parts.push(`${isExpired(entry) ? 'Ended' : 'Access ends'} ${formatDate(entry.expires_at)}`);
    }
    return parts.join(' · ');
  }

  function renderEntry(entry, role) {
    const info = describeEntry(entry, role);
    const item = el('li', `request-item request-${statusLabel(entry)}`);
    const body = el('div', 'request-body');
    const title = el('p', 'request-title');
    title.append(info.before, el('strong', '', entry.username), info.after);
    if (info.chip) title.append(el('span', `chip chip-${info.tone}`, info.chip));
    body.append(title, el('p', 'request-reason', entry.reason));
    if (info.next) body.append(el('p', 'request-next', info.next));

    const actions = el('div', 'request-actions');
    if (role === 'incoming') {
      if (entry.status === 'pending') {
        actions.append(
          makeButton('Approve', () => openApprove(entry), 'primary button small'),
          makeButton('Decline', (button) => rejectRequest(entry, button)),
        );
      } else if (isActive(entry)) {
        actions.append(
          makeButton('Get key package', (button) => showKeyPackage(entry, button), 'primary button small'),
          makeButton('Remove access', () => openRevoke(entry), 'text-danger'),
        );
      }
    } else if (isActive(entry)) {
      if (currentUnlock(entry.id)) {
        actions.append(
          makeButton('Open files', () => openShared(entry), 'primary button small'),
          makeButton('Unlock again', () => openUnlock(entry)),
        );
      } else {
        actions.append(makeButton('Unlock files', () => openUnlock(entry), 'primary button small'));
      }
    }
    const footer = el('div', 'request-footer');
    footer.append(el('p', 'request-dates', describeDates(entry)), actions);
    item.append(body, footer);
    return item;
  }

  // A request is "past" when nothing more can be done with it.
  function isPast(entry) {
    return entry.status === 'rejected' || entry.status === 'revoked' || isExpired(entry);
  }

  // Things that need the user come first, newest first within each group.
  function byPriority(role) {
    const rank = (entry) => {
      if (role === 'incoming') return entry.status === 'pending' ? 0 : 1;
      if (isActive(entry)) return currentUnlock(entry.id) ? 1 : 0;
      return 2; // still waiting for the owner
    };
    return (a, b) => rank(a) - rank(b) || b.id - a.id;
  }

  // How many requests on this side are waiting for the user to act.
  function attentionCount(entries, role) {
    return entries.filter((entry) => !isPast(entry) && (role === 'incoming'
      ? entry.status === 'pending'
      : isActive(entry) && !currentUnlock(entry.id))).length;
  }

  // Draws one side (incoming or outgoing). Finished requests sit in a
  // collapsed "Past requests" section; the tab shows how many need attention.
  function renderSide(side, entries, role) {
    const current = entries.filter((entry) => !isPast(entry)).sort(byPriority(role));
    const past = entries.filter(isPast);
    side.list.replaceChildren(...current.map((entry) => renderEntry(entry, role)));
    side.pastList.replaceChildren(...past.map((entry) => renderEntry(entry, role)));
    side.pastBox.hidden = past.length === 0;
    side.pastSummary.textContent = `Past requests (${past.length})`;

    const attention = attentionCount(entries, role);
    side.count.textContent = String(attention);
    side.count.hidden = attention === 0;

    // The status line only appears when there is nothing open to show. If only
    // finished requests exist, they are opened once so the page is not empty.
    side.status.hidden = current.length > 0;
    if (!current.length) {
      if (past.length) {
        side.status.textContent = role === 'incoming' ? 'No requests are waiting for your review.' : 'You have no open requests.';
        if (!side.pastShown) {
          side.pastBox.open = true;
          side.pastShown = true;
        }
      } else if (role === 'incoming') {
        side.status.textContent = 'No one has asked to see your records yet.';
      } else {
        side.status.textContent = "You haven't asked to see anyone's records yet. Use Request access to start.";
      }
    }
  }

  const incomingSide = {
    list: incomingList, status: incomingStatus, count: $('incoming-count'),
    pastBox: $('incoming-past'), pastList: $('incoming-past-list'), pastSummary: $('incoming-past-summary'),
  };
  const outgoingSide = {
    list: outgoingList, status: outgoingStatus, count: $('outgoing-count'),
    pastBox: $('outgoing-past'), pastList: $('outgoing-past-list'), pastSummary: $('outgoing-past-summary'),
  };

  function renderRequests() {
    renderSide(incomingSide, incoming, 'incoming');
    renderSide(outgoingSide, outgoing, 'outgoing');
  }

  // ------------------------------------------------------------------- tabs
  const tabs = {
    incoming: { tab: $('tab-incoming'), pane: $('pane-incoming') },
    outgoing: { tab: $('tab-outgoing'), pane: $('pane-outgoing') },
  };

  function selectTab(name, focus = false) {
    Object.keys(tabs).forEach((key) => {
      const on = key === name;
      tabs[key].tab.setAttribute('aria-selected', String(on));
      tabs[key].tab.tabIndex = on ? 0 : -1;
      tabs[key].pane.hidden = !on;
    });
    if (focus) tabs[name].tab.focus();
  }

  Object.keys(tabs).forEach((key) => {
    tabs[key].tab.addEventListener('click', () => selectTab(key));
    tabs[key].tab.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      selectTab(key === 'incoming' ? 'outgoing' : 'incoming', true);
    });
  });

  // On the first load, open the tab that has something waiting for the user.
  let firstLoad = true;
  function chooseInitialTab() {
    if (!firstLoad) return;
    firstLoad = false;
    if (!attentionCount(incoming, 'incoming') && attentionCount(outgoing, 'outgoing')) selectTab('outgoing');
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
      pruneUnlocks();
      renderRequests();
      chooseInitialTab();
    } catch (error) {
      if (ticket !== loadCounter) return;
      const text = `Could not load requests. ${error.message}`;
      incomingStatus.textContent = text;
      outgoingStatus.textContent = text;
      incomingStatus.hidden = false;
      outgoingStatus.hidden = false;
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
        requestDialog.close();
        say(`Request sent to ${checked.username}. Their answer will appear under My requests.`);
        selectTab('outgoing');
        await loadRequests();
      } catch (error) {
        requestStatus.classList.add('field-error');
        requestStatus.textContent = error.message;
      }
    });
  });

  $('request-open').addEventListener('click', () => {
    requestStatus.textContent = '';
    requestDialog.showModal();
  });
  $('request-cancel').addEventListener('click', () => requestDialog.close());
  requestDialog.addEventListener('close', () => {
    requestForm.reset();
    $('request-reason-count').textContent = '0';
    requestStatus.textContent = '';
  });

  // ------------------------------------------------------------ owner: reject
  async function rejectRequest(entry, button) {
    await busy(button, async () => {
      try {
        await api(requestUrl(entry.id, '/reject'), { method: 'POST' });
        say(`You declined ${entry.username}'s request.`);
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
    $('approve-title').textContent = `Share your records with ${entry.username}`;
    $('approve-intro').textContent = `Their reason: ${entry.reason}`;
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
        say(`You approved ${target.username}. Now send them the key package so they can unlock the files.`);
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
    $('package-title').textContent = `Send the key package to ${entry.username}`;
    $('package-intro').textContent = `Copy it and send it to ${entry.username} on WhatsApp or email. Only ${entry.username} can open it, using their own MedVault password.`;
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
      status.textContent = 'Copied. Now paste it into WhatsApp or an email.';
    } catch (_) {
      field.focus();
      field.select();
      let copied = false;
      try { copied = document.execCommand('copy'); } catch (__) { copied = false; }
      status.textContent = copied
        ? 'Copied. Now paste it into WhatsApp or an email.'
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
    $('revoke-title').textContent = `Remove access for ${entry.username}?`;
    $('revoke-description').textContent = `${entry.username} will no longer be able to open the files you shared. Anything they already downloaded stays with them.`;
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
        say(`${target.username}'s access was removed.`);
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
      submit.textContent = 'Unlock files';
      return;
    }
    const tick = () => {
      const left = until - Date.now();
      if (left <= 0) {
        window.clearInterval(unlockLockTimer);
        unlockLockTimer = null;
        if (unlockTarget) unlockLockedUntil.delete(unlockTarget.id);
        submit.disabled = false;
        submit.textContent = 'Unlock files';
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
    $('unlock-title').textContent = `Unlock files from ${entry.username}`;
    $('unlock-intro').textContent = `Paste the key package ${entry.username} sent you, then enter your MedVault password.`;
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
        rememberUnlock(target, data);
        renderRequests();
        openShared(target);
        say(`Files from ${target.username} are unlocked.`);
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

  // The unlock state of a request while its 15-minute window is still open.
  function currentUnlock(requestId) {
    const state = unlocked.get(requestId);
    return state && state.unlockedUntil !== null && state.unlockedUntil > Date.now() ? state : null;
  }

  function rememberUnlock(entry, data) {
    unlocked.set(entry.id, {
      files: Array.isArray(data.files) ? data.files : [],
      unlockedUntil: parseDate(data.unlocked_until),
      expiresAt: parseDate(entry.expires_at),
    });
  }

  // Closes the files dialog and empties it, which also removes the preview
  // images. The unlock state itself is kept so the dialog can be reopened.
  function closeShared(reason) {
    sharedOpen = null;
    sharedFiles.replaceChildren();
    if (sharedDialog.open) sharedDialog.close();
    if (reason) say(reason, true);
  }

  // Forgets unlocks that have ended: window over, share expired or revoked.
  // Returns true when something was removed (the list must be redrawn).
  function pruneUnlocks() {
    const now = Date.now();
    let changed = false;
    unlocked.forEach((state, id) => {
      const entry = outgoing.find((candidate) => candidate.id === id);
      let reason = '';
      if (!entry || !isActive(entry)) {
        reason = 'Access to those files has ended. The share was revoked or has expired.';
      } else if (state.unlockedUntil !== null && state.unlockedUntil <= now) {
        reason = 'The 15-minute unlock window ended. Unlock again with the key package and your password to keep viewing.';
      }
      if (!reason) return;
      unlocked.delete(id);
      changed = true;
      if (sharedOpen === id) closeShared(reason);
    });
    return changed;
  }

  function updateDeadlines() {
    const state = sharedOpen === null ? null : unlocked.get(sharedOpen);
    if (!state) return;
    const ends = state.expiresAt === null ? '' : `Access ends ${formatDate(new Date(state.expiresAt).toISOString())}`;
    const left = state.unlockedUntil === null ? '' : `Unlocked for ${formatCountdown(state.unlockedUntil - Date.now())}`;
    $('shared-meta').textContent = [ends, left].filter(Boolean).join(' · ');
  }

  // Runs every second: refreshes the countdown, and when an unlock window or
  // a share ends it closes the dialog and swaps the row's buttons back.
  function tick() {
    updateDeadlines();
    if (unlocked.size && pruneUnlocks()) {
      renderRequests();
      loadRequests();
    }
  }

  function sharedProblem(error) {
    if (error.status === 404) {
      const id = sharedOpen;
      unlocked.delete(id);
      closeShared('Those files are no longer available. The unlock window may have ended or the share was revoked. Unlock again only if the share is still active.');
      renderRequests();
      loadRequests();
    } else {
      $('shared-status').textContent = error.message;
    }
  }

  function renderSharedFile(file, requestId) {
    const item = el('li', 'shared-item');
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

  // Shows the files dialog for a request that has been unlocked. If the
  // unlock window is over, asks for the key package and password again.
  function openShared(entry) {
    const state = currentUnlock(entry.id);
    if (!state) {
      unlocked.delete(entry.id);
      renderRequests();
      openUnlock(entry);
      return;
    }
    sharedOpen = entry.id;
    $('shared-title').textContent = `Files from ${entry.username}`;
    $('shared-status').textContent = state.files.length ? '' : 'No files were shared in this request.';
    sharedFiles.replaceChildren(...state.files.map((file) => renderSharedFile(file, entry.id)));
    updateDeadlines();
    if (!sharedDialog.open) sharedDialog.showModal();
    sharedDialog.scrollTop = 0; // always start at the top, not at the focused element
  }

  $('shared-close').addEventListener('click', () => sharedDialog.close());
  // Also runs when the dialog is closed with the Escape key.
  sharedDialog.addEventListener('close', () => {
    sharedOpen = null;
    sharedFiles.replaceChildren();
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
  sharedTimer = window.setInterval(tick, 1000);
  loadRequests();
})();
