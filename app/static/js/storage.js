(() => {
  const root = document.getElementById('vault');
  const token = root.querySelector('input[name="csrf_token"]').value;
  const base = root.dataset.indexUrl;
  const records = document.getElementById('records');
  const recordsStatus = document.getElementById('records-status');
  const notice = document.getElementById('storage-message');
  const upload = document.getElementById('upload-form');
  const uploadButton = document.getElementById('upload-button');
  const uploadStatus = document.getElementById('upload-status');
  const kind = document.getElementById('kind');
  const file = document.getElementById('file');
  const personal = document.getElementById('personal-form');
  const personalSave = document.getElementById('personal-save');
  const personalCancel = document.getElementById('personal-cancel');
  const filter = document.getElementById('record-filter');
  const compareStatus = document.getElementById('comparison-status');
  const compareResult = document.getElementById('comparison-result');
  const compareRows = document.getElementById('comparison-rows');
  const dialog = document.getElementById('delete-dialog');
  const deleteConfirm = document.getElementById('delete-confirm');
  const deleteCancel = document.getElementById('delete-cancel');
  const deleteError = document.getElementById('delete-error');
  const types = {
    id_card: {label: 'Identity scan', accept: '.jpg,.jpeg,.png', hint: 'JPG, JPEG or PNG'},
    document: {label: 'Medical document', accept: '.pdf,.doc,.docx,.xls,.xlsx', hint: 'PDF, DOC, DOCX, XLS or XLSX'},
    video: {label: 'Symptom video', accept: '.mp4', hint: 'MP4 video'},
    personal_data: {label: 'Personal data'}
  };
  const viewDialog = document.getElementById('view-dialog');
  const viewFields = document.getElementById('view-fields');
  const viewImage = document.getElementById('view-image');
  const viewError = document.getElementById('view-error');
  const viewStatus = document.getElementById('view-status');
  const personalFields = ['nama', 'nik', 'alamat', 'tanggal_lahir'];
  let viewRequest = 0;
  let items = [];
  let editingId = null;
  let selectedId = null;
  let compareRequest = 0;
  let deleteItem = null;
  let deleteTrigger = null;
  let page = 0;
  const pageSize = 3;

  const size = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(2)} KiB`;
    return `${(bytes / 1048576).toFixed(2)} MiB`;
  };
  function say(text, isError = false) {
    notice.textContent = text;
    notice.hidden = !text;
    notice.classList.toggle('error-notice', isError);
  }
  async function request(url, options = {}) {
    let response;
    try { response = await fetch(url, options); }
    catch (_) { throw new Error('Connection failed. Check your connection and try again.'); }
    if (response.redirected || response.status === 401) throw new Error('Your session may have expired. Log in again to continue.');
    if (!response.ok) {
      if (response.status === 413) throw new Error('The upload is too large for the configured request limit or the 50 MiB file limit.');
      if (response.status === 404) throw new Error('This record is unavailable. Refresh your list and try again.');
      if (response.status === 422) throw new Error('This record could not be read or decrypted.');
      if (response.status === 400) {
        const type = response.headers.get('content-type') || '';
        if (!type.includes('application/json')) throw new Error('The form may have expired. Refresh the page and try again; unsaved details will be lost.');
        const data = await response.json();
        const messages = {
          'File tidak ditemukan': 'Choose a file to upload.',
          'Ekstensi file tidak diizinkan': 'This file format is not allowed for the selected category.',
          'Format file tidak valid': 'This file format is not supported.',
          'File kosong': 'The file is empty. Choose another file.',
          'File gambar tidak valid': 'This image could not be verified. Choose a valid JPG or PNG file.',
          'File PDF tidak valid': 'This PDF could not be verified. Choose a valid PDF file.',
          'File MP4 tidak valid': 'This video could not be verified. Choose a valid MP4 file.',
          'NIK harus 16 digit': 'NIK must contain exactly 16 digits.',
          'tanggal_lahir tidak boleh di masa depan': 'Date of birth cannot be in the future.'
        };
        throw new Error(messages[data.error] || 'The information or file could not be accepted. Check the fields and file format, then try again.');
      }
      throw new Error(`Something went wrong (${response.status}). Please try again.`);
    }
    return response;
  }
  function post(body, json = false) {
    const headers = {'X-CSRFToken': token};
    if (json) headers['Content-Type'] = 'application/json';
    return {method: 'POST', headers, body};
  }
  function makeButton(label, action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'subtle-button';
    button.textContent = label;
    button.addEventListener('click', () => action(button));
    return button;
  }
  function displayName(item) { return item.kind === 'personal_data' ? `Personal record #${item.id}` : item.name; }
  function resetPersonal() {
    personal.reset(); editingId = null; personalSave.textContent = 'Create record'; personalCancel.hidden = true;
  }
  function clearComparison() {
    compareRequest += 1; selectedId = null; compareResult.hidden = true; compareRows.replaceChildren(); compareStatus.textContent = '';
  }
  function render() {
    records.replaceChildren();
    document.getElementById('file-count').textContent = String(items.filter((item) => item.kind !== 'personal_data').length);
    document.getElementById('personal-count').textContent = String(items.filter((item) => item.kind === 'personal_data').length);
    document.getElementById('total-size').textContent = size(items.reduce((sum, item) => sum + item.size, 0));
    const visible = items.filter((item) => filter.value === 'all' || item.kind === filter.value);
    recordsStatus.textContent = visible.length ? `${visible.length} ${visible.length === 1 ? 'record' : 'records'}` : (items.length ? 'No records in this category.' : 'Your vault is ready. Add your first record or upload a file.');
    const pageCount = Math.ceil(visible.length / pageSize);
    page = Math.min(page, Math.max(0, pageCount - 1));
    document.getElementById('records-pagination').hidden = pageCount <= 1;
    document.getElementById('records-previous').disabled = page === 0;
    document.getElementById('records-next').disabled = page >= pageCount - 1;
    document.getElementById('records-page').textContent = `Page ${page + 1} of ${pageCount}`;
    visible.slice(page * pageSize, (page + 1) * pageSize).forEach((item) => {
      const row = document.createElement('li'); row.className = 'record-item';
      const meta = document.createElement('div'); meta.className = 'record-meta';
      const name = document.createElement('strong'); name.textContent = displayName(item);
      const detail = document.createElement('small'); detail.textContent = `${types[item.kind]?.label || 'Record'} · ${size(item.size)} original`;
      meta.append(name, detail);
      const actions = document.createElement('div'); actions.className = 'record-actions';
      const download = document.createElement('a');
      download.className = 'record-download';
      download.href = `${base}${item.id}/download/AES`;
      download.textContent = 'Download original';
      download.setAttribute('aria-label', `Download ${displayName(item)} from its AES copy`);
      actions.append(download, makeButton('Compare methods', () => showComparison(item)));
      if (item.kind === 'personal_data' || item.kind === 'id_card') actions.append(makeButton('View', () => viewRecord(item)));
      if (item.kind === 'personal_data') actions.append(makeButton('Edit', () => editPersonal(item)));
      actions.append(makeButton('Delete', (button) => openDelete(item, button)));
      row.append(meta, actions); records.append(row);
    });
  }
  async function refresh() {
    recordsStatus.textContent = 'Loading records...';
    try {
      const response = await request(base);
      const data = await response.json(); items = data.items;
      if (selectedId !== null && !items.some((item) => item.id === selectedId)) clearComparison();
      render();
    } catch (error) {
      recordsStatus.textContent = `Could not load records. ${error.message}`;
      throw error;
    }
  }
  async function showComparison(item) {
    const requestId = ++compareRequest; selectedId = item.id;
    compareResult.hidden = true; compareStatus.textContent = 'Loading comparison...';
    document.getElementById('comparison').scrollIntoView({behavior: 'smooth', block: 'start'});
    try {
      const response = await request(`${base}${item.id}/comparison`);
      const data = await response.json();
      if (requestId !== compareRequest) return;
      document.getElementById('comparison-name').textContent = displayName(item);
      document.getElementById('comparison-original').textContent = `Original size: ${data.original_size} bytes (${size(data.original_size)})`;
      compareRows.replaceChildren();
      for (const algorithm of ['AES', 'DES', 'RC4']) {
        const copy = data.copies.find((entry) => entry.algorithm === algorithm);
        const tr = document.createElement('tr');
        const overhead = copy && Number.isFinite(copy.encrypted_size) ? copy.encrypted_size - data.original_size : null;
        const percent = overhead !== null && data.original_size > 0 ? ` (${(100 * overhead / data.original_size).toFixed(2)}%)` : '';
        const milliseconds = copy && Number.isFinite(copy.encryption_seconds) ? copy.encryption_seconds * 1000 : null;
        const time = milliseconds === null ? 'Unavailable' : (milliseconds > 0 && milliseconds < 0.00005 ? '<0.0001 ms' : `${milliseconds.toFixed(4)} ms`);
        const values = [algorithm, copy ? (copy.mode || 'Stream (no mode)') : 'Unavailable', time, copy && Number.isFinite(copy.encrypted_size) ? `${copy.encrypted_size} bytes` : 'Unavailable', overhead === null ? 'Unavailable' : `${overhead >= 0 ? '+' : ''}${overhead} bytes${percent}`];
        values.forEach((value, index) => {
          const cell = document.createElement(index === 0 ? 'th' : 'td');
          if (index === 0) { cell.scope = 'row'; cell.className = 'algorithm-name'; }
          cell.textContent = value;
          tr.append(cell);
        });
        const download = document.createElement('td');
        if (copy) { const link = document.createElement('a'); link.href = `${base}${item.id}/download/${algorithm}`; link.textContent = `Download ${algorithm}`; download.append(link); }
        else download.textContent = 'Unavailable';
        tr.append(download); compareRows.append(tr);
      }
      compareResult.hidden = false; compareStatus.textContent = '';
    } catch (error) { if (requestId === compareRequest) compareStatus.textContent = error.message; }
  }
  async function editPersonal(item) {
    try {
      const response = await request(`${base}${item.id}/personal`);
      const data = await response.json();
      for (const field of ['nama', 'nik', 'alamat', 'tanggal_lahir']) personal.elements.namedItem(field).value = data[field];
      editingId = item.id; personalSave.textContent = 'Save changes'; personalCancel.hidden = false;
      document.getElementById('personal').scrollIntoView({behavior: 'smooth'}); personal.elements.nama.focus();
      say('Editing personal information.');
    } catch (error) { say(error.message, true); }
  }
  function openDelete(item, trigger) {
    deleteItem = item; deleteTrigger = trigger; deleteError.textContent = '';
    document.getElementById('delete-description').textContent = `Delete ${displayName(item)}?`;
    dialog.showModal(); deleteCancel.focus();
  }
  dialog.addEventListener('close', () => { if (deleteTrigger && deleteTrigger.isConnected) deleteTrigger.focus(); });
  dialog.addEventListener('cancel', (event) => { if (deleteConfirm.disabled) event.preventDefault(); });
  deleteConfirm.addEventListener('click', async () => {
    if (!deleteItem) return;
    deleteConfirm.disabled = true; deleteCancel.disabled = true; deleteError.textContent = '';
    try {
      const id = deleteItem.id;
      await request(`${base}${id}/delete`, post(null));
      if (id === editingId) resetPersonal();
      if (id === selectedId) clearComparison();
      dialog.close(); deleteItem = null;
      try { await refresh(); say('Record deleted.'); }
      catch (_) { say('Record deleted, but the list could not be refreshed. Use Refresh to try again.', true); }
    } catch (error) { deleteError.textContent = error.message; }
    finally { deleteConfirm.disabled = false; deleteCancel.disabled = false; }
  });
  kind.addEventListener('change', () => { file.value = ''; file.accept = types[kind.value].accept; document.getElementById('format-hint').textContent = types[kind.value].hint; document.getElementById('file-name').textContent = 'No file selected'; });
  file.addEventListener('change', () => { document.getElementById('file-name').textContent = file.files.length ? `${file.files[0].name} · ${size(file.files[0].size)}` : 'No file selected'; });
  upload.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!file.files.length) return;
    const requestLimit = Number(root.dataset.maxRequest);
    if (file.files[0].size > 50 * 1048576 || (requestLimit && file.files[0].size >= requestLimit)) { say('The selected file is too large for the upload limit.', true); return; }
    const payload = new FormData(upload);
    uploadButton.disabled = true; kind.disabled = true; file.disabled = true; uploadStatus.textContent = 'Uploading and encrypting...'; say('');
    try {
      await request(root.dataset.uploadUrl, post(payload));
      upload.reset(); file.accept = types[kind.value].accept; document.getElementById('format-hint').textContent = types[kind.value].hint; document.getElementById('file-name').textContent = 'No file selected';
      try { await refresh(); say('File added to your vault.'); }
      catch (_) { say('File uploaded, but the list could not be refreshed. Use Refresh to try again.', true); }
    } catch (error) { say(error.message, true); }
    finally { uploadButton.disabled = false; kind.disabled = false; file.disabled = false; uploadStatus.textContent = ''; }
  });
  personal.addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(personal).entries());
    const isEdit = editingId !== null;
    const url = isEdit ? `${base}${editingId}/personal/update` : root.dataset.personalUrl;
    personalSave.disabled = true;
    try {
      await request(url, post(JSON.stringify(payload), true));
      if (editingId === selectedId) clearComparison();
      resetPersonal();
      try { await refresh(); say(isEdit ? 'Personal information updated.' : 'Personal record created.'); }
      catch (_) { say('Personal information saved, but the list could not be refreshed. Use Refresh to try again.', true); }
    } catch (error) { say(error.message, true); }
    finally { personalSave.disabled = false; }
  });
  personalCancel.addEventListener('click', () => { resetPersonal(); say('Editing cancelled.'); });
  filter.addEventListener('change', () => { page = 0; render(); });
  document.getElementById('records-previous').addEventListener('click', () => { page -= 1; render(); });
  document.getElementById('records-next').addEventListener('click', () => { page += 1; render(); });
  document.getElementById('refresh-records').addEventListener('click', async () => { try { await refresh(); say('Records refreshed.'); } catch (error) { say(error.message, true); } });
  
  function clearView() {
  viewRequest += 1;
  personalFields.forEach((f) => { document.getElementById(`view-${f}`).textContent = ''; });
  viewFields.hidden = true; viewImage.hidden = true; viewImage.removeAttribute('src');
  viewError.textContent = ''; viewStatus.textContent = '';
}

async function viewRecord(item) {
  clearView();
  const requestId = viewRequest;
  document.getElementById('view-title').textContent = displayName(item);
  viewDialog.showModal();
  if (item.kind === 'personal_data') {
    viewStatus.textContent = 'Decrypting...';
    try {
      const data = await (await request(`${base}${item.id}/personal`)).json();
      if (requestId !== viewRequest) return;           // dialog sudah ditutup
      personalFields.forEach((f) => { document.getElementById(`view-${f}`).textContent = data[f]; });
      viewFields.hidden = false; viewStatus.textContent = '';
    } catch (error) { if (requestId === viewRequest) { viewStatus.textContent = ''; viewError.textContent = error.message; } }
  } else if (item.kind === 'id_card') {
    viewImage.alt = `Decrypted preview of ${item.name}`;
    viewImage.src = `${base}${item.id}/view`;
    viewImage.hidden = false;
  }
}

viewImage.addEventListener('error', () => {
  if (!viewImage.getAttribute('src')) return;
  viewImage.hidden = true;
  viewError.textContent = 'The image could not be decrypted or displayed.';
});
// Hapus data hasil dekripsi dari DOM begitu dialog ditutup.
viewDialog.addEventListener('close', clearView);
  
  refresh().catch((error) => say(error.message, true));
})();

