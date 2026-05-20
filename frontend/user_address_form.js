// GENERATED -- do not edit. Regenerate: make gen

const _UserAddressFields = [
    {name: 'line1', label: 'Street Address', required: true},
    {name: 'line2', label: 'Apt / Suite', required: false},
    {name: 'city', label: 'City', required: true},
    {name: 'state', label: 'State / Province', required: true},
    {name: 'postcode', label: 'Postcode', required: true},
    {name: 'country', label: 'Country', required: true}
];

function buildUserAddressForm() {
    const form = document.getElementById('user_address-fields');
    if (!form) return;
    form.innerHTML = '';
    _UserAddressFields.forEach(f => {
        const label = document.createElement('label');
        label.textContent = f.label;
        label.style.cssText = 'display:block;font-size:0.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;margin-top:16px;margin-bottom:4px';
        const input = document.createElement('input');
        input.type = 'text';
        input.id = 'user_address_' + f.name;
        input.placeholder = f.label;
        input.style.cssText = 'width:100%;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#c9d1d9;font-size:0.9rem;padding:10px 14px;outline:none;box-sizing:border-box';
        form.appendChild(label);
        form.appendChild(input);
    });
}

async function loadUserAddress() {
    try {
        const r = await fetch('/user_address');
        if (!r.ok) return;
        const data = await r.json();
        _UserAddressFields.forEach(f => {
            const el = document.getElementById('user_address_' + f.name);
            if (el) el.value = data[f.name] || '';
        });
    } catch (_) {}
}

async function saveUserAddress() {
    const statusEl = document.getElementById('user_address-status');
    const data = {};
    for (const f of _UserAddressFields) {
        const val = (document.getElementById('user_address_' + f.name)?.value || '').trim();
        if (f.required && !val) {
            if (statusEl) statusEl.textContent = f.label + ' is required';
            return;
        }
        data[f.name] = val;
    }
    try {
        const r = await fetch('/user_address', {
            method:  'POST',
            headers: {'Content-Type': 'application/json'},
            body:    JSON.stringify(data)
        });
        if (statusEl) statusEl.textContent = r.ok ? 'Saved' : 'Save failed';
    } catch (_) {
        if (statusEl) statusEl.textContent = 'Connection error';
    }
}
