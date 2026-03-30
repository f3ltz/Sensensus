export const shortKey = (hex, start = 8, end = 6) =>
  hex ? `${hex.slice(0, start)}…${hex.slice(-end)}` : "—";

export const fmtTime = (ts) =>
  new Date(ts * 1000).toLocaleTimeString("en-US", { hour12: false });

export const fmtDuration = (seconds) => {
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
};

export const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

export function quatToCss(qw, qx, qy, qz) {
  const n = Math.sqrt(qw * qw + qx * qx + qy * qy + qz * qz) || 1;
  const [w, x, y, z] = [qw / n, qx / n, qy / n, qz / n];
  const m = [
    1 - 2 * (y * y + z * z), 2 * (x * y - z * w),   2 * (x * z + y * w),   0,
    2 * (x * y + z * w),     1 - 2 * (x * x + z * z), 2 * (y * z - x * w),   0,
    2 * (x * z - y * w),     2 * (y * z + x * w),   1 - 2 * (x * x + y * y), 0,
    0, 0, 0, 1,
  ];
  return `matrix3d(${m.join(",")})`;
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function parseCsvLine(line) {
  const parts = line.trim().split(",");
  if (parts.length < 8) return null;
  const [, ax, ay, az, qw, qx, qy, qz] = parts.map(Number);
  if ([ax, ay, az, qw, qx, qy, qz].some(isNaN)) return null;
  return { ax, ay, az, qw, qx, qy, qz };
}

// Derive aggregate stats from settled events
export function computeStats(events) {
  if (!events.length) return { dropRate: 0, avgCswarm: 0, slashCount: 0, totalEvents: 0 };
  const drops = events.filter((e) => e.consensus_verdict).length;
  const slashes = events.filter((e) => e.transporter_slashed).length;
  const avgCswarm = events.reduce((s, e) => s + e.cswarm, 0) / events.length;
  return {
    dropRate: (drops / events.length) * 100,
    avgCswarm: avgCswarm * 100,
    slashCount: slashes,
    totalEvents: events.length,
  };
}

const aliasCache = {};
let tCount = 1;
let aCount = 1;

export function getNodeAlias(id, role = "Auditor") {
  if (!id) return "—";

  if (aliasCache[id]) {
    if (role === "Transporter" && aliasCache[id].startsWith("Auditor")) {
      aliasCache[id] = `Transporter-${tCount++}`;
    }
    return aliasCache[id];
  }
 
  if (role === "Transporter") {
    aliasCache[id] = `Transporter-${tCount++}`;
  } else {
    aliasCache[id] = `Auditor-${String.fromCharCode(64 + aCount++)}`; 
  }
  return aliasCache[id];
}