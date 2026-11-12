'use strict';

let sysctlPlan;
let sysctlBusy = false;

function renderSysctl() {
  $('sysctl-plan').disabled = sysctlBusy;
  $('sysctl-apply').disabled = sysctlBusy || !sysctlPlan || sysctlPlan.managed || !sysctlPlan.settings.some(v => v.target > v.current);
  $('sysctl-restore').disabled = sysctlBusy || !sysctlPlan?.managed;
  const list = $('sysctl-settings');
  list.replaceChildren();
  if (!sysctlPlan) {
    $('sysctl-skipped').textContent = '';
    return;
  }
  const p = sysctlPlan;
  $('sysctl-status').textContent = `${p.cpus} логических ЦП · ${p.memory_mib} МиБ RAM · ${p.managed ? 'профиль сохранён' : 'предпросмотр'}`;
  for (const v of p.settings) {
    const row = node('div', '', 'flex flex-wrap justify-between gap-2 py-3 text-sm');
    row.append(node('dt', v.key, 'font-mono'), node('dd', `${v.current} → ${v.target}`));
    list.append(row);
  }
  $('sysctl-skipped').textContent = p.skipped.length ? 'Ядро не предоставило: ' + p.skipped.join(', ') : '';
}

async function refreshSysctl(action) {
  if (sysctlBusy) return;
  sysctlBusy = true;
  renderSysctl();
  try {
    sysctlPlan = action
      ? await api('/sysctl/' + action, {method: 'POST', body: JSON.stringify({token: sysctlPlan?.token || ''})})
      : await api('/sysctl');
    if (action) message(action === 'apply' ? 'Профиль sysctl применён и сохранён.' : 'Прежние значения sysctl восстановлены.');
  } catch (e) {
    sysctlPlan = null;
    $('sysctl-status').textContent = e.message;
  } finally {
    sysctlBusy = false;
    renderSysctl();
  }
}

$('sysctl-plan').addEventListener('click', () => void refreshSysctl());
$('sysctl-apply').addEventListener('click', () => void refreshSysctl('apply'));
$('sysctl-restore').addEventListener('click', () => void refreshSysctl('restore'));
