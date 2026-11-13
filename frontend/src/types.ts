export type PingMethod = 'icmp-tcp' | 'icmp' | 'tcp' | 'masscan';
export type RangeMode = 'range' | 'cidr';
export type DisplayFilter = 'all' | 'alive' | 'dead' | 'open';
export type SortKey = 'ip' | 'hostname' | 'ports' | 'status' | 'ping' | `port:${number}`;

export interface HostResult {
  ip: string;
  ipNum: number;
  hostname: string;
  alive: boolean;
  pingMs: number | null;
  method: string;
  openPorts: number[];
  portsScanned: boolean;
}

export interface ScanOptions {
  threads: number;
  timeoutMs: number;
  pingMethod: PingMethod;
  ports: number[];
  resolveHostnames: boolean;
  scanPorts: boolean;
  portsAliveOnly: boolean;
}

export interface TargetInput {
  mode: RangeMode;
  start: string;
  end: string;
  cidr: string;
}

export interface AppInfo {
  version: string;
  os: string;
  mobile: boolean;
  icmpAvailable: boolean;
  masscanAvailable: boolean;
  masscanDriver: boolean;
  defaultStart: string;
  defaultEnd: string;
  defaultCidr: string;
  testTarget: string;
  maxThreads: number;
}

export interface RangePreview {
  ok: boolean;
  count: number;
  label: string;
  error: string;
}

export interface StartInfo {
  id: number;
  total: number;
  label: string;
  pingMethod: PingMethod;
}

export interface ScanProgress {
  id: number;
  scanned: number;
  total: number;
  alive: number;
  dead: number;
  running: boolean;
}

export interface ScanFinished {
  id: number;
  cancelled: boolean;
  elapsedMs: number;
  scanned: number;
  alive: number;
}

export interface RowsBatch {
  id: number;
  rows: HostResult[];
}