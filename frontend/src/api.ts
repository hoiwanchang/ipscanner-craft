import { invoke } from '@tauri-apps/api/core';
import type {
  AppInfo,
  HostResult,
  RangePreview,
  ScanOptions,
  StartInfo,
  TargetInput,
} from './types';

export const appInfo = () => invoke<AppInfo>('app_info');

export const previewRange = (target: TargetInput) =>
  invoke<RangePreview>('preview_range', { target });

export const startScan = (id: number, target: TargetInput, options: ScanOptions) =>
  invoke<StartInfo>('start_scan', { id, target, options });

export const stopScan = () => invoke<void>('stop_scan');

export const rescanHost = (ip: string, options: ScanOptions) =>
  invoke<HostResult>('rescan_host', { ip, options });

export const exportResults = (
  path: string,
  format: 'csv' | 'json',
  rows: HostResult[],
  ports: number[],
  range: string,
) => invoke<string>('export_results', { path, format, rows, ports, range });

export const openInBrowser = (host: string, port: number, https: boolean) =>
  invoke<void>('open_in_browser', { host, port, https });

export const screenshotTarget = () => invoke<string | null>('screenshot_target');

export const saveScreenshot = (data: string) => invoke<void>('save_screenshot', { data });

export const MAX_CHECKED_PORTS = 1024;
export const SUMMARY_COLUMN_THRESHOLD = 8;

/// Ports are digits only; anything else that is not a range joiner splits.
/// Users can separate with commas, Chinese commas, spaces, slashes, pipes…
const RANGE_CHARS = '-~～–—';

export function parsePorts(text: string): number[] {
  const seen = new Set<number>();
  let token = '';
  const flush = () => {
    if (!token) return;
    const parts = token.split('').filter((c) => RANGE_CHARS.includes(c) || /\d/.test(c)).join('');
    const m = parts.match(/^(\d+)(?:[-~～–—](\d+))?$/);
    token = '';
    if (!m) return;
    const a = Number(m[1]);
    const b = Number(m[2] ?? m[1]);
    if (!Number.isInteger(a) || !Number.isInteger(b)) return;
    const lo = Math.max(1, Math.min(a, b));
    const hi = Math.min(65535, Math.max(a, b));
    for (let p = lo; seen.size < MAX_CHECKED_PORTS && p <= hi; p++) seen.add(p);
  };
  for (const ch of text) {
    if (/\d/.test(ch) || RANGE_CHARS.includes(ch)) {
      token += ch;
    } else {
      flush();
    }
  }
  flush();
  return [...seen].sort((a, b) => a - b).slice(0, MAX_CHECKED_PORTS);
}

/// "80,443,8000-8010" compression for dense displays.
export function compressPorts(ports: number[], maxItems = 14): string {
  if (ports.length === 0) return '';
  const sorted = [...ports].sort((a, b) => a - b);
  const groups: string[] = [];
  let start = sorted[0];
  let prev = sorted[0];
  for (const p of sorted.slice(1)) {
    if (p === prev + 1) {
      prev = p;
      continue;
    }
    groups.push(start === prev ? `${start}` : `${start}-${prev}`);
    start = prev = p;
  }
  groups.push(start === prev ? `${start}` : `${start}-${prev}`);
  if (groups.length <= maxItems) return groups.join(', ');
  return groups.slice(0, maxItems).join(', ') + ` +${groups.length - maxItems}`;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const holder = document.createElement('textarea');
    holder.value = text;
    holder.style.position = 'fixed';
    holder.style.opacity = '0';
    document.body.appendChild(holder);
    holder.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch {
      ok = false;
    }
    holder.remove();
    return ok;
  }
}