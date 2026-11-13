<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, triggerRef, watch } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { downloadDir } from '@tauri-apps/api/path';
import ToolBar from './components/ToolBar.vue';
import ResultsTable from './components/ResultsTable.vue';
import StatusBar from './components/StatusBar.vue';
import ContextMenu from './components/ContextMenu.vue';
import PreferencesDialog from './components/PreferencesDialog.vue';
import ExportDialog from './components/ExportDialog.vue';
import DetailsDialog from './components/DetailsDialog.vue';
import * as api from './api';
import type {
  AppInfo,
  DisplayFilter,
  HostResult,
  PingMethod,
  RangeMode,
  RowsBatch,
  ScanFinished,
  ScanOptions,
  ScanProgress,
  SortKey,
} from './types';

const info = ref<AppInfo | null>(null);

/// Stock defaults; user edits persist over them in localStorage. user edits persist over them in localStorage.
const DEFAULTS = {
  mode: 'range' as RangeMode,
  start: '192.168.1.1',
  end: '192.168.1.254',
  cidr: '192.168.1.1/24',
  threads: 50,
  timeoutMs: 1000,
  pingMethod: 'icmp-tcp' as PingMethod,
  portsText: '80, 443, 22',
  resolveHostnames: true,
  scanPorts: true,
  portsAliveOnly: true,
};
const SETTINGS_KEY = 'ipscanner-settings';

function loadSettings(): Partial<typeof DEFAULTS> {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
  } catch {
    return { ...DEFAULTS };
  }
}

const saved = loadSettings();
const mode = ref<RangeMode>(saved.mode ?? DEFAULTS.mode);
const start = ref(saved.start ?? DEFAULTS.start);
const end = ref(saved.end ?? DEFAULTS.end);
const cidr = ref(saved.cidr ?? DEFAULTS.cidr);

const threads = ref(saved.threads ?? DEFAULTS.threads);
const timeoutMs = ref(saved.timeoutMs ?? DEFAULTS.timeoutMs);
const pingMethod = ref<PingMethod>(saved.pingMethod ?? DEFAULTS.pingMethod);
const portsText = ref(saved.portsText ?? DEFAULTS.portsText);
const resolveHostnames = ref(saved.resolveHostnames ?? DEFAULTS.resolveHostnames);
const scanPorts = ref(saved.scanPorts ?? DEFAULTS.scanPorts);
const portsAliveOnly = ref(saved.portsAliveOnly ?? DEFAULTS.portsAliveOnly);

function persistSettings() {
  try {
    localStorage.setItem(
      SETTINGS_KEY,
      JSON.stringify({
        mode: mode.value,
        start: start.value,
        end: end.value,
        cidr: cidr.value,
        threads: threads.value,
        timeoutMs: timeoutMs.value,
        pingMethod: pingMethod.value,
        portsText: portsText.value,
        resolveHostnames: resolveHostnames.value,
        scanPorts: scanPorts.value,
        portsAliveOnly: portsAliveOnly.value,
      }),
    );
  } catch {
    /* storage full or unavailable — defaults still work next launch */
  }
}

watch(
  [mode, start, end, cidr, threads, timeoutMs, pingMethod, portsText, resolveHostnames, scanPorts, portsAliveOnly],
  persistSettings,
);

const filter = ref<DisplayFilter>('all');
const sortKey = ref<SortKey>('ip');
const sortDir = ref<'asc' | 'desc'>('asc');
const theme = ref<'light' | 'dark'>('light');

const rows = shallowRef<HostResult[]>([]);
const progress = ref<ScanProgress>({
  id: 0,
  scanned: 0,
  total: 0,
  alive: 0,
  dead: 0,
  running: false,
});
const scanning = ref(false);
const stateText = ref('Ready');
const rangeLabel = ref('');
const selectedIp = ref<string | null>(null);

const preview = ref({ ok: true, count: 254, label: '', error: '' });
const menu = ref<{ row: HostResult; x: number; y: number } | null>(null);
const showPreferences = ref(false);
const showExport = ref(false);
const details = ref<HostResult | null>(null);
const confirmLarge = ref(false);
const toast = ref<{ text: string; error: boolean } | null>(null);
const baseDir = ref('');

const unlisten: UnlistenFn[] = [];
let toastTimer = 0;
let flushPending = false;
let previewTimer = 0;

const ports = computed(() => api.parsePorts(portsText.value));

const options = computed<ScanOptions>(() => ({
  threads: threads.value,
  timeoutMs: timeoutMs.value,
  pingMethod: pingMethod.value,
  ports: ports.value,
  resolveHostnames: resolveHostnames.value,
  scanPorts: scanPorts.value,
  portsAliveOnly: portsAliveOnly.value,
}));

const target = computed(() => ({
  mode: mode.value,
  start: start.value,
  end: end.value,
  cidr: cidr.value,
}));

const hint = computed(() => {
  if (!preview.value.ok) return preview.value.error;
  const count = preview.value.count.toLocaleString();
  return preview.value.count > 65536
    ? `${count} addresses — this will take a while`
    : `${count} addresses`;
});

function matches(row: HostResult) {
  if (filter.value === 'alive') return row.alive;
  if (filter.value === 'dead') return !row.alive;
  if (filter.value === 'open') return row.openPorts.length > 0;
  return true;
}

function portRank(row: HostResult, port: number) {
  if (!row.portsScanned) return 2;
  return row.openPorts.includes(port) ? 0 : 1;
}

const shown = computed(() => {
  const list = rows.value.filter(matches);
  const key = sortKey.value;
  const direction = sortDir.value === 'asc' ? 1 : -1;
  const port = key.startsWith('port:') ? Number(key.slice(5)) : 0;
  list.sort((a, b) => {
    let delta = 0;
    if (key === 'ip') delta = a.ipNum - b.ipNum;
    else if (key === 'hostname') delta = a.hostname.localeCompare(b.hostname);
    else if (key === 'ports') delta = a.openPorts.length - b.openPorts.length;
    else if (key === 'status') delta = Number(b.alive) - Number(a.alive);
    else if (key === 'ping')
      delta = (a.pingMs ?? Number.MAX_VALUE) - (b.pingMs ?? Number.MAX_VALUE);
    else delta = portRank(a, port) - portRank(b, port);
    if (delta === 0) delta = a.ipNum - b.ipNum;
    return delta * direction;
  });
  return list;
});

function notify(text: string, error = false) {
  toast.value = { text, error };
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toast.value = null), error ? 6000 : 3200);
}

function scheduleFlush() {
  if (flushPending) return;
  flushPending = true;
  window.setTimeout(() => {
    flushPending = false;
    triggerRef(rows);
  }, 90);
}

function refreshPreview() {
  window.clearTimeout(previewTimer);
  previewTimer = window.setTimeout(async () => {
    try {
      preview.value = await api.previewRange(target.value);
    } catch (error) {
      preview.value = { ok: false, count: 0, label: '', error: String(error) };
    }
  }, 180);
}

watch([mode, start, end, cidr], refreshPreview);

function applyTheme() {
  document.documentElement.setAttribute('data-theme', theme.value);
  localStorage.setItem('ipscanner-theme', theme.value);
}

function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark';
  applyTheme();
}

async function beginScan() {
  if (!preview.value.ok) {
    notify(preview.value.error, true);
    return;
  }
  if (preview.value.count > 65536) {
    confirmLarge.value = true;
    return;
  }
  await launch();
}

async function launch() {
  confirmLarge.value = false;
  rows.value = [];
  triggerRef(rows);
  selectedIp.value = null;
  const id = Date.now();
  progress.value = { id, scanned: 0, total: preview.value.count, alive: 0, dead: 0, running: true };
  try {
    const started = await api.startScan(id, target.value, options.value);
    rangeLabel.value = started.label;
    scanning.value = true;
    stateText.value = `Scanning ${started.label}…`;
    if (started.pingMethod === 'tcp' && pingMethod.value !== 'tcp') {
      notify('ICMP is unavailable here, so hosts are probed over TCP.');
    }
  } catch (error) {
    scanning.value = false;
    progress.value = { ...progress.value, running: false };
    stateText.value = 'Ready';
    notify(String(error), true);
  }
}

async function halt() {
  await api.stopScan();
  stateText.value = 'Stopping…';
}

function onSort(key: SortKey) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc';
  } else {
    sortKey.value = key;
    sortDir.value = 'asc';
  }
}

function rowAsText(row: HostResult) {
  return [
    row.ip,
    row.hostname,
    row.alive ? 'alive' : 'dead',
    row.pingMs === null ? '' : row.pingMs.toFixed(1),
    row.openPorts.join(' '),
  ].join(',');
}

async function runAction(name: string) {
  const row = menu.value?.row;
  if (!row) return;
  if (name === 'copy-ip') {
    const copied = await api.copyText(row.ip);
    notify(copied ? `Copied ${row.ip}` : 'Could not reach the clipboard', !copied);
  } else if (name === 'copy-host') {
    await api.copyText(row.hostname);
    notify(`Copied ${row.hostname}`);
  } else if (name === 'copy-row') {
    await api.copyText(rowAsText(row));
    notify('Copied the row');
  } else if (name === 'open-http' || name === 'open-https') {
    const https = name === 'open-https';
    const preferred = https ? 443 : 80;
    const port = row.openPorts.includes(preferred)
      ? preferred
      : (row.openPorts[0] ?? preferred);
    try {
      await api.openInBrowser(row.hostname || row.ip, port, https);
    } catch (error) {
      notify(String(error), true);
    }
  } else if (name === 'rescan') {
    await rescan(row);
  } else if (name === 'details') {
    details.value = row;
  }
}

async function rescan(row: HostResult) {
  notify(`Rescanning ${row.ip}…`);
  try {
    const fresh = await api.rescanHost(row.ip, options.value);
    const index = rows.value.findIndex((r) => r.ip === fresh.ip);
    if (index >= 0) rows.value[index] = fresh;
    else rows.value.push(fresh);
    triggerRef(rows);
    if (details.value?.ip === fresh.ip) details.value = fresh;
    notify(`${fresh.ip} is ${fresh.alive ? 'alive' : 'not answering'}`);
  } catch (error) {
    notify(String(error), true);
  }
}

function stamp() {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

const suggestedPath = ref('');

function openExport() {
  suggestedPath.value = `${baseDir.value}ipscan-${stamp()}.csv`;
  showExport.value = true;
}

async function doExport(value: { path: string; format: 'csv' | 'json'; scope: 'shown' | 'all' }) {
  const list = value.scope === 'shown' ? shown.value : rows.value;
  try {
    const written = await api.exportResults(
      value.path,
      value.format,
      list,
      ports.value,
      rangeLabel.value || preview.value.label,
    );
    showExport.value = false;
    notify(`Saved ${list.length} rows to ${written}`);
  } catch (error) {
    notify(String(error), true);
  }
}

function applyPreferences(value: {
  threads: number;
  timeoutMs: number;
  pingMethod: PingMethod;
  portsText: string;
  resolveHostnames: boolean;
  scanPorts: boolean;
  portsAliveOnly: boolean;
}) {
  threads.value = value.threads;
  timeoutMs.value = value.timeoutMs;
  pingMethod.value = value.pingMethod;
  portsText.value = value.portsText;
  resolveHostnames.value = value.resolveHostnames;
  scanPorts.value = value.scanPorts;
  portsAliveOnly.value = value.portsAliveOnly;
}

function onGlobalKey(event: KeyboardEvent) {
  if (event.key !== 'Escape') return;
  if (menu.value) menu.value = null;
  else if (details.value) details.value = null;
  else if (showExport.value) showExport.value = false;
  else if (showPreferences.value) showPreferences.value = false;
  else if (confirmLarge.value) confirmLarge.value = false;
}

onMounted(async () => {
  const stored = localStorage.getItem('ipscanner-theme');
  theme.value = stored === 'dark' || stored === 'light' ? stored : 'light';
  applyTheme();
  window.addEventListener('keydown', onGlobalKey);

  try {
    const loaded = await api.appInfo();
    info.value = loaded;
    if (!loaded.icmpAvailable) pingMethod.value = 'tcp';
    stateText.value = loaded.mobile ? 'Ready — TCP probing on this device' : 'Ready';
  } catch (error) {
    notify(String(error), true);
  }

  try {
    const dir = await downloadDir();
    baseDir.value = dir.endsWith('/') || dir.endsWith('\\') ? dir : `${dir}/`;
  } catch {
    baseDir.value = '';
  }

  refreshPreview();

  unlisten.push(
    await listen<RowsBatch>('scan://rows', (event) => {
      if (event.payload.id !== progress.value.id) return;
      rows.value.push(...event.payload.rows);
      scheduleFlush();
    }),
  );
  unlisten.push(
    await listen<ScanProgress>('scan://progress', (event) => {
      if (event.payload.id !== progress.value.id) return;
      progress.value = event.payload;
    }),
  );
  unlisten.push(
    await listen<{ id: number; error: string }>('scan://error', (event) => {
      scanning.value = false;
      progress.value = { ...progress.value, running: false };
      stateText.value = `Scan failed: ${event.payload.error}`;
    }),
  );
  unlisten.push(
    await listen<ScanFinished>('scan://done', (event) => {
      if (event.payload.id !== progress.value.id) return;
      scanning.value = false;
      triggerRef(rows);
      const seconds = (event.payload.elapsedMs / 1000).toFixed(1);
      stateText.value = event.payload.cancelled
        ? `Stopped after ${event.payload.scanned} addresses (${seconds}s)`
        : `Finished ${rangeLabel.value} in ${seconds}s`;
    }),
  );
});

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onGlobalKey);
  unlisten.forEach((stop) => stop());
});
</script>

<template>
  <div class="app">
    <ToolBar
      v-model:mode="mode"
      v-model:start="start"
      v-model:end="end"
      v-model:cidr="cidr"
      v-model:threads="threads"
      v-model:timeout-ms="timeoutMs"
      v-model:ping-method="pingMethod"
      v-model:ports-text="portsText"
      v-model:filter="filter"
      :theme="theme"
      :scanning="scanning"
      :icmp-available="info?.icmpAvailable ?? true"
      :mobile="info?.mobile ?? false"
      :hint="hint"
      :hint-bad="!preview.ok || preview.count > 65536"
      @toggle-theme="toggleTheme"
      @start="beginScan"
      @stop="halt"
      @preferences="showPreferences = true"
      @export="openExport"
    />

    <ResultsTable
      :rows="shown"
      :ports="ports"
      :sort-key="sortKey"
      :sort-dir="sortDir"
      :selected-ip="selectedIp"
      :scanning="scanning"
      @sort="onSort"
      @select="(row) => (selectedIp = row.ip)"
      @context="(payload) => (menu = payload)"
      @details="(row) => (details = row)"
    />

    <StatusBar
      :state="stateText"
      :scanned="progress.scanned"
      :total="progress.total"
      :alive="progress.alive"
      :dead="progress.dead"
      :shown="shown.length"
      :scanning="scanning"
    />

    <ContextMenu
      v-if="menu"
      :row="menu.row"
      :x="menu.x"
      :y="menu.y"
      @close="menu = null"
      @action="runAction"
    />

    <PreferencesDialog
      v-if="showPreferences"
      :threads="threads"
      :timeout-ms="timeoutMs"
      :ping-method="pingMethod"
      :ports-text="portsText"
      :resolve-hostnames="resolveHostnames"
      :scan-ports="scanPorts"
      :ports-alive-only="portsAliveOnly"
      :icmp-available="info?.icmpAvailable ?? true"
      :masscan-available="info?.masscanAvailable ?? false"
      :masscan-driver="info?.masscanDriver ?? false"
      :mobile="info?.mobile ?? false"
      @close="showPreferences = false"
      @apply="applyPreferences"
    />

    <ExportDialog
      v-if="showExport"
      :suggested-path="suggestedPath"
      :count="rows.length"
      :shown="shown.length"
      @close="showExport = false"
      @submit="doExport"
    />

    <DetailsDialog
      v-if="details"
      :row="details"
      :ports="ports"
      @close="details = null"
      @rescan="details && rescan(details)"
    />

    <div v-if="confirmLarge" class="overlay" @mousedown.self="confirmLarge = false">
      <div class="dialog">
        <h2>That is a lot of addresses</h2>
        <div class="body">
          <p class="note">
            {{ preview.count.toLocaleString() }} addresses will be probed. With
            {{ threads }} threads this can take a long time. Continue?
          </p>
        </div>
        <div class="footer">
          <button @click="confirmLarge = false">Cancel</button>
          <button class="primary" @click="launch">Start anyway</button>
        </div>
      </div>
    </div>

    <div v-if="toast" class="toast" :class="{ error: toast.error }">{{ toast.text }}</div>
  </div>
</template>