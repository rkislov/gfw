'use strict';

const identitySources = {local: 'Локальная база', ldap: 'LDAP', radius: 'RADIUS', either: 'Локальная база или LDAP'};
const vpnNames = {openvpn: 'OpenVPN', ipsec: 'IKEv2', wireguard: 'WireGuard'};

function vpnMethod(form) {
  const auth = {password: form.elements.auth_password.value, certificate: form.elements.auth_certificate.checked, totp: form.elements.auth_totp.checked};
  return auth;
}

function setVPNMethod(form, auth) {
  form.elements.auth_password.value = auth?.password || '';
  form.elements.auth_certificate.checked = auth?.certificate ?? true;
  form.elements.auth_totp.checked = auth?.totp ?? false;
}

function submitIdentityForm(id, handler, onError = e => message(e.message)) {
  $(id).addEventListener('submit', async e => {
    e.preventDefault();
    const form = e.currentTarget;
    if (e.submitter) e.submitter.disabled = true;
    try { await handler(form, Object.fromEntries(new FormData(form))); }
    catch (err) { onError(err); }
    finally { if (e.submitter) e.submitter.disabled = false; }
  });
}

function identityWrite(path, method, body) {
  return api(path, {method, body: JSON.stringify(body)});
}

submitIdentityForm('personal-login', async (form, data) => {
  $('login-error').textContent = '';
  try {
    await identityWrite('/auth/login', 'POST', data);
    await enter();
  } finally {
    form.elements.password.value = '';
    form.elements.code.value = '';
  }
}, err => { $('login-error').textContent = err.message; });

function resetPortal() {
  $('portal-totp-start').reset();
  $('portal-totp-confirm').reset();
  $('portal-totp-confirm').hidden = true;
  $('portal-totp-secret').textContent = '';
  $('portal-profiles').replaceChildren();
  $('portal-account').textContent = '';
}

async function downloadPortalProfile(p) {
  const response = await fetch('/api/v1/portal/export', {
    method: 'POST', credentials: 'same-origin',
    headers: {'X-GFW-CSRF': csrf, 'Content-Type': 'application/json'},
    body: JSON.stringify({id: p.id})
  });
  if (!response.ok) throw new Error((await response.json()).error);
  const href = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = href;
  link.download = response.headers.get('Content-Disposition')?.match(/filename="([^"]+)"/)?.[1] || 'gfw-vpn';
  link.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}

async function refreshPortal() {
  try {
    const account = currentAccount;
    const {user, profiles} = await api('/portal');
    if (currentAccount !== account) return;
    $('portal-account').textContent = `${user.name} · ${identitySources[user.source]} · 2FA ${user.totp ? 'включена' : 'не настроена'}`;
    $('portal-totp-start').hidden = user.totp;
    const list = $('portal-profiles');
    list.replaceChildren();
    for (const p of profiles) {
      const kind = p.id.split(':')[0];
      const row = node('div', '', 'py-3');
      row.append(node('p', `${vpnNames[kind]} · ${p.name}`, 'font-medium'));
      if (p.endpoint) row.append(node('p', p.endpoint, 'text-sm text-slate-600'));
      if (p.networks?.length) row.append(node('p', p.networks.join(', '), 'text-sm text-slate-600'));
      if (p.auth?.totp) {
        const hint = p.auth.password ? 'Введите пароль:код. Например, после пароля добавьте :123456.' : 'Введите текущий код приложения в поле пароля VPN.';
        row.append(node('p', hint, 'text-sm text-slate-600'));
      }
      const button = node('button', p.ready ? 'Скачать конфигурацию' : 'Профиль пока недоступен', 'mt-2 text-sm text-teal-800 disabled:opacity-40');
      button.disabled = !p.ready;
      button.addEventListener('click', async () => {
        button.disabled = true;
        try { await downloadPortalProfile(p); }
        catch (e) { message(e.message); }
        finally { button.disabled = false; }
      });
      row.append(button);
      list.append(row);
    }
    if (!profiles.length) list.append(node('p', 'Администратор ещё не назначил VPN-профили.', 'py-3 text-sm text-slate-600'));
  } catch (e) { message(e.message); }
}

submitIdentityForm('portal-totp-start', async (form, data) => {
  try {
    const enrollment = await identityWrite('/portal/totp/begin', 'POST', data);
    $('portal-totp-secret').textContent = enrollment.secret;
    $('portal-totp-confirm').hidden = false;
    $('portal-totp-confirm').elements.code.focus();
  } finally { form.reset(); }
});

submitIdentityForm('portal-totp-confirm', async (form, data) => {
  try {
    await identityWrite('/portal/totp/confirm', 'POST', data);
    resetPortal();
    csrf = '';
    currentAccount = null;
    $('app').hidden = true;
    $('login').hidden = false;
    $('login-error').textContent = '2FA подключена. Для входа дождитесь следующего кода приложения.';
  } finally { form.reset(); }
});

function grantValues(text) { return [...new Set(text.split(/[\s,]+/).filter(Boolean))]; }

function identityFill(form, values) {
  form.reset();
  for (const [key, value] of Object.entries(values)) {
    const field = form.elements[key];
    if (!field || field.type === 'password') continue;
    if (field.type === 'checkbox') field.checked = value;
    else field.value = Array.isArray(value) ? value.join('\n') : value;
  }
}

async function refreshIdentityUsers() {
  try {
    const [users, ldap, radius] = await Promise.all([api('/users'), api('/users/ldap'), api('/users/radius')]);
    const list = $('identity-users');
    list.replaceChildren();
    for (const user of users) {
      const button = node('button', `${user.name} · ${identitySources[user.source]} · ${user.role === 'admin' ? 'Администратор' : 'Пользователь VPN'}${user.disabled ? ' · Заблокирован' : ''}${user.totp ? ' · 2FA' : ''}`, 'block py-2 text-left text-sm text-teal-800');
      button.addEventListener('click', () => {
        const form = $('identity-user');
        identityFill(form, user);
        form.elements.name.readOnly = true;
        form.elements.source.disabled = true;
      });
      list.append(button);
    }
    if (!users.length) list.append(node('p', 'Создайте первую учётную запись.', 'text-sm text-slate-600'));
    identityFill($('identity-ldap'), ldap);
    identityFill($('identity-radius'), radius);
    void refreshGrantOptions();
  } catch (e) { message(e.message); }
}

async function refreshGrantOptions() {
  const [ovpn, wg, ike] = await Promise.allSettled([api('/openvpn/runtime/state'), api('/wireguard/state'), api('/ipsec/state')]);
  const select = $('identity-grant');
  select.replaceChildren(new Option('Выберите профиль', ''));
  for (const i of ovpn.value?.agent?.confirmed?.instances || []) {
    if (i.enabled && i.mode === 'server') select.add(new Option('OpenVPN · ' + i.name, 'openvpn:' + i.id));
  }
  for (const t of wg.value?.confirmed?.tunnels || []) {
    if (t.enabled) for (const peer of t.peers || []) {
      if (peer.enabled && peer.key_ref) select.add(new Option(`WireGuard · ${t.name} / ${peer.name}`, `wireguard:${t.id}:${peer.id}`));
    }
  }
  for (const t of ike.value?.agent?.confirmed?.tunnels || []) {
    if (t.enabled && t.auth) select.add(new Option('IKEv2 · ' + t.name, 'ipsec:' + t.id));
  }
}
$('identity-grant').addEventListener('change', e => {
  const field = $('identity-user').elements.grants;
  if (e.target.value) field.value = grantValues(field.value + '\n' + e.target.value).join('\n');
  e.target.value = '';
});

$('identity-user').addEventListener('reset', e => {
  e.currentTarget.elements.name.readOnly = false;
  e.currentTarget.elements.source.disabled = false;
});

submitIdentityForm('identity-user', async (form, data) => {
  await identityWrite('/users', 'PUT', {
    ...data, source: form.elements.source.value, revision: Number(data.revision), grants: grantValues(data.grants), disabled: form.elements.disabled.checked,
    reset_totp: form.elements.reset_totp.checked
  });
  form.elements.password.value = '';
  form.elements.reset_totp.checked = false;
  message('Учётная запись сохранена.');
  await refreshIdentityUsers();
});
for (const service of ['ldap', 'radius']) {
  submitIdentityForm('identity-' + service, async (form, data) => {
    await identityWrite('/users/' + service, 'PUT', data);
    form.querySelector('input[type=password]').value = '';
    message('Настройки сохранены.');
  });
}
