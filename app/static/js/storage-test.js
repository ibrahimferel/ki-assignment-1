(() => {
  const root = document.querySelector('#storage-test');
  if (!root) return;

  const token = document.querySelector('input[name="csrf_token"]').value;
  const message = document.querySelector('#storage-message');
  const records = document.querySelector('#records');
  const personalForm = document.querySelector('#personal-form');
  const uploadForm = document.querySelector('#upload-form');
  const cancel = document.querySelector('#personal-cancel');
  const save = document.querySelector('#personal-save');
  const base = root.dataset.indexUrl;
  let editingId = null;

  function say(text) { message.textContent = text; }
  function resetPersonal() {
    personalForm.reset();
    editingId = null;
    save.textContent = 'Create record';
    cancel.hidden = true;
  }
  async function request(url, options = {}) {
    const response = await fetch(url, options);
    if (response.redirected) throw new Error('Your session may have expired. Please log in again.');
    if (!response.ok) {
      let detail = `Request failed (${response.status}).`;
      if ((response.headers.get('content-type') || '').includes('application/json')) {
        const body = await response.json();
        if (body.error) detail = body.error;
      }
      throw new Error(detail);
    }
    return response;
  }
  function postOptions(body, json = false) {
    const headers = { 'X-CSRFToken': token };
    if (json) headers['Content-Type'] = 'application/json';
    return { method: 'POST', headers, body };
  }
  function button(label, action) {
    const element = document.createElement('button');
    element.type = 'button';
    element.textContent = label;
    element.addEventListener('click', action);
    return element;
  }
  async function refresh() {
    const response = await request(base);
    const data = await response.json();
    records.replaceChildren();
    if (!data.items.length) {
      const item = document.createElement('li');
      item.textContent = 'No records yet.';
      records.append(item);
      return;
    }
    for (const record of data.items) {
      const item = document.createElement('li');
      const label = document.createElement('span');
      label.textContent = `${record.name} (${record.kind}, ${record.size} bytes) `;
      item.append(label);
      for (const algorithm of ['AES', 'DES', 'RC4']) {
        const link = document.createElement('a');
        link.href = `${base}${record.id}/download/${algorithm}`;
        link.textContent = `Download ${algorithm}`;
        item.append(link, document.createTextNode(' '));
      }
      if (record.kind === 'personal_data') {
        item.append(button('Edit', async () => {
          try {
            const response = await request(`${base}${record.id}/personal`);
            const data = await response.json();
            for (const name of ['nama', 'nik', 'alamat', 'tanggal_lahir']) {
              personalForm.elements.namedItem(name).value = data[name];
            }
            editingId = record.id;
            save.textContent = 'Save changes';
            cancel.hidden = false;
            say('Editing personal data.');
            personalForm.elements.namedItem('nama').focus();
          } catch (error) { say(error.message); }
        }), document.createTextNode(' '));
      }
      item.append(button('Delete', async () => {
        if (!window.confirm(`Delete ${record.name}?`)) return;
        try {
          await request(`${base}${record.id}/delete`, postOptions(null));
          if (editingId === record.id) resetPersonal();
          await refresh();
          say('Record deleted.');
        } catch (error) { say(error.message); }
      }));
      records.append(item);
    }
  }
  personalForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const fields = new FormData(personalForm);
    const payload = Object.fromEntries(fields.entries());
    const isEdit = editingId !== null;
    const url = isEdit ? `${base}${editingId}/personal/update` : root.dataset.personalUrl;
    try {
      await request(url, postOptions(JSON.stringify(payload), true));
      resetPersonal();
      await refresh();
      say(isEdit ? 'Personal data updated.' : 'Personal data created.');
    } catch (error) { say(error.message); }
  });
  uploadForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await request(root.dataset.uploadUrl, postOptions(new FormData(uploadForm)));
      uploadForm.reset();
      await refresh();
      say('File uploaded.');
    } catch (error) { say(error.message); }
  });
  cancel.addEventListener('click', () => { resetPersonal(); say('Editing cancelled.'); });
  document.querySelector('#refresh-records').addEventListener('click', async () => {
    try { await refresh(); say('List refreshed.'); } catch (error) { say(error.message); }
  });
  refresh().catch((error) => say(error.message));
})();
