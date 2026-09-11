/* Cipher Station admin panel — vanilla JS, no build step. */
"use strict";

const $ = (id) => document.getElementById(id);

/* ---------------- theme (System / Light / Dark) ----------------
   The inline <head> script already applied the stored choice before first
   paint; this wires the toggle and keeps localStorage in sync. */
function themeChoice() {
  try { return localStorage.getItem("panel_theme") || "system"; }
  catch (_) { return "system"; }
}

function applyTheme(choice) {
  const html = document.documentElement;
  if (choice === "light" || choice === "dark") {
    html.setAttribute("data-theme", choice);
  } else {
    html.removeAttribute("data-theme");  // back to prefers-color-scheme
    choice = "system";
  }
  try {
    if (choice === "system") localStorage.removeItem("panel_theme");
    else localStorage.setItem("panel_theme", choice);
  } catch (_) {}
  document.querySelectorAll(".theme-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.themeChoice === choice));
}

document.querySelectorAll(".theme-btn").forEach((btn) =>
  btn.addEventListener("click", () => applyTheme(btn.dataset.themeChoice)));
applyTheme(themeChoice());

/* ---------------- per-boot token auth ---------------- */
let TOKEN = sessionStorage.getItem("panel_token") || "";

function showLogin(message) {
  $("login-err").textContent = message || "";
  $("login").classList.remove("hidden");
  $("login-token").focus();
}

function authHeaders(extra = {}) {
  return Object.assign({ "Authorization": "Bearer " + TOKEN }, extra);
}

const api = async (path, opts = {}) => {
  opts.headers = authHeaders(opts.headers || {});
  const res = await fetch(path, opts);
  if (res.status === 401) {
    showLogin(TOKEN ? "Token rejected — the station may have restarted." : "");
    throw new Error("panel token required");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const obj = await res.json();
      detail = (typeof obj.detail === "string" ? obj.detail
                : obj.detail && obj.detail.detail) || detail;
    } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
};

const postJson = (path, body) => api(path, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

/* Authenticated binary fetch → object URL (img/video/iframe src and download
   links cannot carry the Authorization header themselves). */
async function fetchBlobUrl(path) {
  const res = await fetch(path, { headers: authHeaders() });
  if (res.status === 401) { showLogin(); throw new Error("panel token required"); }
  if (!res.ok) throw new Error(res.statusText);
  return URL.createObjectURL(await res.blob());
}

$("login-go").addEventListener("click", () => {
  const t = $("login-token").value.trim();
  if (!t) return;
  TOKEN = t;
  sessionStorage.setItem("panel_token", t);
  $("login").classList.add("hidden");
  $("login-token").value = "";
  cfgLoaded = false;
  driveState.loaded = false;
  loadDashboard();
});
$("login-token").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("login-go").click();
});

function toast(text, danger = false) {
  const el = $("toast");
  el.textContent = text;
  el.classList.toggle("danger", danger);
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 2500);
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(
    () => toast("Copied"),
    () => toast("Copy failed", true),
  );
}

document.addEventListener("click", (e) => {
  const c = e.target.closest(".copyable");
  if (c && c.textContent && c.textContent !== "—") copyText(c.textContent.trim());
});

/* ---------------- tabs ---------------- */
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    $("tab-" + btn.dataset.tab).classList.remove("hidden");
    if (btn.dataset.tab === "drive") loadDrive();
    if (btn.dataset.tab === "config") loadConfig();
    if (btn.dataset.tab === "registry") loadRegistry();
  });
});

/* ---------------- helpers ---------------- */
function fmtBytes(n) {
  if (n == null) return "?";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}
function fmtUptime(s) {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${s % 60}s`;
}
function fmtDate(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/* ---------------- dashboard ---------------- */

async function loadDashboard() {
  try {
    const s = await api("/admin/api/status");
    $("dash-loading").classList.add("hidden");
    $("dash-error").classList.add("hidden");
    $("dash-body").classList.remove("hidden");

    $("d-status").innerHTML = '<span class="dot"></span>Running';
    $("d-version").textContent = (s.version || "?") + (s.commit ? ` (${s.commit})` : "");
    $("d-uptime").textContent = fmtUptime(s.uptime_seconds);
    $("d-uid").textContent = s.uid || "—";
    $("d-endpoint").textContent = s.endpoint || "(not published yet)";
    $("d-peer").textContent = s.peer_id || "(unknown)";
    $("d-ipns").textContent = s.ipns_name || "(unknown)";

    const t = s.tunnel || {};
    if (t.permanent_url) {
      $("d-url-mode").textContent = "permanent";
      $("d-url-note").textContent = "";
    } else if (t.quick_tunnel_enabled) {
      $("d-url-mode").textContent = "quick tunnel";
      $("d-url-note").textContent = "URL rotates on restart.";
    } else {
      $("d-url-mode").textContent = "none";
      $("d-url-note").textContent = "Configure a public URL in Configuration.";
    }

    const ipfs = s.ipfs || {};
    $("d-ipfs-status").innerHTML = ipfs.running
      ? '<span class="dot"></span>Running'
      : '<span class="dot down"></span>Down';
    $("d-ipfs-status").style.color = ipfs.running ? "" : "var(--danger)";
    if (ipfs.running) {
      $("d-ipfs-used").textContent =
        `${fmtBytes(ipfs.repo_size_bytes)} of ${fmtBytes(ipfs.storage_max_bytes)} (${ipfs.used_percent}%)`;
      $("d-ipfs-meter").style.width = Math.min(100, ipfs.used_percent || 0) + "%";
    } else {
      $("d-ipfs-used").textContent = ipfs.error ? "unavailable" : "—";
    }
  } catch (err) {
    $("dash-loading").classList.add("hidden");
    $("dash-body").classList.add("hidden");
    const el = $("dash-error");
    el.textContent = "Could not load station status: " + err.message;
    el.classList.remove("hidden");
  }
}

loadDashboard();
setInterval(loadDashboard, 15000);

/* ---------------- config ---------------- */
let cfgLoaded = false;

async function loadConfig(force = false) {
  if (cfgLoaded && !force) return;
  try {
    const c = await api("/admin/api/config");
    cfgLoaded = true;
    $("cfg-loading").classList.add("hidden");
    $("cfg-error").classList.add("hidden");
    $("cfg-body").classList.remove("hidden");

    $("c-alias").value = c.alias || "";
    const p = c.profile || {};
    $("c-display").value = p.display_name || "";
    $("c-username").value = p.username || "";
    $("c-bio").value = p.bio || "";
    $("c-link").value = p.link || "";
    $("c-tunnel").checked = !!c.cloudflare_tunnel_enabled;
    $("c-storage").value = c.ipfs_storage_max || "";
    if (c.registry_enabled) $("registry-tab-btn").classList.remove("hidden");
    loadPublicUrl();
  } catch (err) {
    $("cfg-loading").classList.add("hidden");
    const el = $("cfg-error");
    el.textContent = "Could not load configuration: " + err.message;
    el.classList.remove("hidden");
  }
}

function setMsg(id, text, isErr = false) {
  const el = $(id);
  el.textContent = text;
  el.classList.toggle("err", isErr);
  if (text) setTimeout(() => { el.textContent = ""; }, 4000);
}

$("c-save-profile").addEventListener("click", async () => {
  try {
    await postJson("/admin/api/config", { alias: $("c-alias").value });
    await postJson("/admin/api/profile", {
      display_name: $("c-display").value,
      username: $("c-username").value,
      bio: $("c-bio").value,
      link: $("c-link").value,
    });
    setMsg("c-profile-msg", "Saved.");
  } catch (err) {
    setMsg("c-profile-msg", err.message, true);
  }
});

$("c-save-storage").addEventListener("click", async () => {
  try {
    await postJson("/admin/api/config/storage-max", { storage_max: $("c-storage").value });
    setMsg("c-storage-msg", "Saved.");
    $("c-storage-restart").classList.remove("hidden");
    $("c-storage-badge").classList.remove("hidden");
  } catch (err) {
    setMsg("c-storage-msg", err.message, true);
  }
});

/* ---------------- Public URL modes ---------------- */
let puState = { mode: "quick" };

function puSelectMode(mode) {
  puState.mode = mode;
  document.querySelectorAll(".mode-option").forEach((o) => {
    const isIt = o.dataset.mode === mode;
    o.classList.toggle("selected", isIt);
    o.querySelector("input").checked = isIt;
  });
  ["quick", "domain", "grant"].forEach((m) =>
    $(`pu-${m}-settings`).classList.toggle("hidden", m !== mode));
}

document.querySelectorAll(".mode-option input").forEach((r) =>
  r.addEventListener("change", () => puSelectMode(r.value)));

async function loadPublicUrl() {
  try {
    const u = await api("/admin/api/public-url");
    puSelectMode(u.mode || "quick");

    const banner = $("pu-banner");
    if (u.degraded) {
      banner.textContent = u.degraded;
      banner.classList.remove("hidden");
    } else {
      banner.classList.add("hidden");
    }

    $("pu-quick-url").textContent = (u.quick && u.quick.url) || "—";

    const d = u.domain || {};
    if (d.hostname) $("pu-hostname").value = d.hostname;
    if (d.zone) $("pu-zone").value = d.zone;
    if (d.driver) $("pu-driver").value = d.driver;
    puTokenHint();
    const pf = d.port_forward || {};
    $("pu-fwd-port").textContent = pf.port || "8443";
    $("pu-fwd-lan").textContent = pf.lan_ip ? pf.lan_ip + ":" + (pf.port || "8443") : "this station";
    const ddns = d.ddns;
    $("pu-ddns-status").textContent = !ddns ? "not running"
      : ddns.state === "ok" ? "active" + (ddns.last_ips && ddns.last_ips.ipv4 ? ` (${ddns.last_ips.ipv4})` : "")
      : ddns.state + (ddns.error ? `: ${ddns.error}` : "");

    const g = u.grant || {};
    if (g.registry_url) $("pu-registry-url").value = g.registry_url;
    if (g.name) $("pu-grant-name").value = g.name;
    if (g.zone) $("pu-grant-zone").value = g.zone;
  } catch (err) {
    toast("Could not load public URL settings: " + err.message, true);
  }
}

function puTokenHint() {
  const driver = $("pu-driver").value;
  const env = driver === "vercel" ? "VERCEL_API_TOKEN" : "CLOUDFLARE_API_TOKEN";
  $("pu-token-hint").textContent =
    `Set ${env} in the station's .env (never stored by the panel).`;
}
$("pu-driver").addEventListener("change", puTokenHint);

$("pu-save").addEventListener("click", async () => {
  const body = { mode: puState.mode };
  $("pu-hostname-err").classList.add("hidden");
  $("pu-hostname").classList.remove("invalid");
  if (puState.mode === "quick") {
    try {
      await postJson("/admin/api/config",
        { cloudflare_tunnel_enabled: $("c-tunnel").checked });
    } catch (err) { setMsg("pu-msg", err.message, true); return; }
  } else if (puState.mode === "domain") {
    body.hostname = $("pu-hostname").value.trim();
    body.zone = $("pu-zone").value.trim();
    body.driver = $("pu-driver").value;
  } else if (puState.mode === "grant") {
    body.registry_url = $("pu-registry-url").value.trim();
    body.grant_name = $("pu-grant-name").value.trim();
    body.grant_zone = $("pu-grant-zone").value.trim();
  }
  try {
    const res = await postJson("/admin/api/public-url", body);
    setMsg("pu-msg", "Saved.");
    (res.warnings || []).forEach((w) => toast(w, true));
    if (res.restart_required) {
      $("pu-restart-cmd").textContent = res.restart_command || "sudo systemctl restart cipherstation";
      $("pu-restart-note").classList.remove("hidden");
      $("pu-restart-badge").classList.remove("hidden");
    }
    loadPublicUrl();
  } catch (err) {
    if (puState.mode === "domain" && /hostname|zone/.test(err.message)) {
      $("pu-hostname").classList.add("invalid");
      const el = $("pu-hostname-err");
      el.textContent = err.message;
      el.classList.remove("hidden");
    }
    setMsg("pu-msg", err.message, true);
  }
});

$("pu-grant-check").addEventListener("click", async () => {
  const el = $("pu-grant-status");
  el.textContent = "Checking…";
  try {
    const r = await postJson("/admin/api/public-url/grant/check", {
      name: $("pu-grant-name").value.trim(),
      zone: $("pu-grant-zone").value.trim(),
    });
    el.textContent = r.available ? "Available."
      : `Not available (${r.reason || "taken"}).`;
  } catch (err) {
    el.textContent = "Check failed: " + err.message;
  }
});

$("pu-grant-claim").addEventListener("click", async () => {
  const el = $("pu-grant-status");
  el.textContent = "Claiming…";
  try {
    const s = await api("/admin/api/status");
    const target = s.endpoint || "";
    if (!target) { el.textContent = "No station endpoint to point the name at yet."; return; }
    const host = target.replace(/^https?:\/\//, "").replace(/[:/].*$/, "");
    const r = await postJson("/admin/api/public-url/grant/claim", {
      name: $("pu-grant-name").value.trim(),
      zone: $("pu-grant-zone").value.trim(),
      target: host, record_type: "CNAME",
    });
    el.textContent = "Claimed." + (r.dns_synced === false ? " (DNS pending on the registry side.)" : "");
  } catch (err) {
    el.textContent = "Claim failed: " + err.message;
  }
});

$("pu-grant-release").addEventListener("click", async () => {
  if (!confirm("Release this name back to the registry?")) return;
  const el = $("pu-grant-status");
  try {
    await postJson("/admin/api/public-url/grant/release", {
      name: $("pu-grant-name").value.trim(),
      zone: $("pu-grant-zone").value.trim(),
    });
    el.textContent = "Released.";
  } catch (err) {
    el.textContent = "Release failed: " + err.message;
  }
});

/* ---------------- registry admin tab ---------------- */
async function loadRegistry() {
  $("rg-loading").classList.remove("hidden");
  $("rg-error").classList.add("hidden");
  try {
    const r = await api("/admin/api/registry");
    $("rg-loading").classList.add("hidden");
    $("rg-body").classList.remove("hidden");
    renderRegistry(r);
  } catch (err) {
    $("rg-loading").classList.add("hidden");
    const el = $("rg-error");
    el.textContent = "Could not load the registry: " + err.message;
    el.classList.remove("hidden");
  }
}

function renderRegistry(r) {
  const zones = r.zones || {};
  const zoneNames = Object.keys(zones);

  const zbox = $("rg-zones");
  zbox.innerHTML = "";
  if (!zoneNames.length) {
    zbox.innerHTML = '<p class="hint">No zones configured. Add them to ' +
      '<span class="mono">registry.json</span> in the data directory.</p>';
  }
  zoneNames.forEach((z) => {
    const zc = zones[z];
    const div = document.createElement("div");
    div.className = "kv";
    const left = document.createElement("span");
    left.className = "mono";
    left.textContent = z;
    const right = document.createElement("span");
    right.innerHTML =
      `<span class="badge accent">${zc.claim_mode}</span> ` +
      `<span class="badge">${zc.driver || "no driver"}</span> ` +
      (zc.token_present ? '<span class="badge">token ok</span>'
                        : '<span class="badge" style="color:var(--danger)">token missing</span>');
    div.append(left, right);
    zbox.appendChild(div);
  });

  const claims = r.claims || [];
  $("rg-claims-empty").classList.toggle("hidden", claims.length > 0);
  $("rg-claims-table").classList.toggle("hidden", claims.length === 0);
  const tbody = $("rg-claims");
  tbody.innerHTML = "";
  claims.forEach((c) => {
    const tr = document.createElement("tr");
    const cells = [c.name, c.zone, c.target, c.record_type,
                   fmtDate(c.last_heartbeat), fmtDate(c.expires_at)];
    cells.forEach((v, i) => {
      const td = document.createElement("td");
      td.textContent = v ?? "—";
      if (i === 0 || i === 2) td.classList.add("mono");
      tr.appendChild(td);
    });
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "btn small danger-btn";
    btn.textContent = "Revoke";
    btn.addEventListener("click", async () => {
      if (!confirm(`Revoke ${c.name}.${c.zone}? Its DNS record is deleted.`)) return;
      try {
        await postJson("/admin/api/registry/revoke", { name: c.name, zone: c.zone });
        toast(`Revoked ${c.name}.${c.zone}`);
        loadRegistry();
      } catch (err) { toast("Revoke failed: " + err.message, true); }
    });
    act.appendChild(btn);
    tr.appendChild(act);
    tbody.appendChild(tr);
  });

  const inviteSel = $("rg-invite-zone");
  const reservedSel = $("rg-reserved-zone");
  [inviteSel, reservedSel].forEach((sel) => {
    sel.innerHTML = "";
    zoneNames.forEach((z) => {
      const o = document.createElement("option");
      o.value = z; o.textContent = z;
      sel.appendChild(o);
    });
  });
  reservedSel.onchange = () => {
    const z = reservedSel.value;
    $("rg-reserved-list").value = (zones[z] ? zones[z].reserved_extra || [] : []).join("\n");
  };
  if (zoneNames.length) reservedSel.onchange();

  const ibox = $("rg-invites");
  ibox.innerHTML = "";
  (r.invites || []).forEach((inv) => {
    const div = document.createElement("div");
    div.className = "kv";
    div.innerHTML =
      `<span class="mono copyable" title="Click to copy">${inv.code}</span>` +
      `<span class="hint" style="margin:0">${inv.zone} · ` +
      (inv.used_at ? `used by ${inv.used_by_name}` : "unused") + `</span>`;
    ibox.appendChild(div);
  });
}

$("rg-invite-new").addEventListener("click", async () => {
  try {
    const r = await postJson("/admin/api/registry/invite",
                             { zone: $("rg-invite-zone").value });
    toast("Invite issued: " + r.code);
    loadRegistry();
  } catch (err) { toast("Invite failed: " + err.message, true); }
});

$("rg-reserved-save").addEventListener("click", async () => {
  const names = $("rg-reserved-list").value.split("\n")
    .map((s) => s.trim()).filter(Boolean);
  try {
    await postJson("/admin/api/registry/reserved",
                   { zone: $("rg-reserved-zone").value, reserved: names });
    setMsg("rg-reserved-msg", "Saved.");
    loadRegistry();
  } catch (err) { setMsg("rg-reserved-msg", err.message, true); }
});

/* ---------------- drive ---------------- */
let driveState = { files: [], folders: [], filter: null, loaded: false };

async function loadDrive(force = false) {
  if (driveState.loaded && !force) { renderDrive(); return; }
  $("dr-loading").classList.remove("hidden");
  $("dr-error").classList.add("hidden");
  $("dr-empty").classList.add("hidden");
  $("dr-table").classList.add("hidden");
  try {
    const d = await api("/admin/api/drive/files");
    driveState.files = d.files || [];
    driveState.folders = d.folders || [];
    driveState.metaErrors = d.errors || [];
    driveState.loaded = true;
    $("dr-loading").classList.add("hidden");
    renderDrive();
  } catch (err) {
    $("dr-loading").classList.add("hidden");
    const el = $("dr-error");
    el.textContent = "Could not load the drive: " + err.message;
    el.classList.remove("hidden");
  }
}

function renderDrive() {
  // Folder chips
  const chips = $("dr-folders");
  chips.innerHTML = "";
  const mk = (label, value) => {
    const b = document.createElement("button");
    b.className = "chip" + (driveState.filter === value ? " active" : "");
    b.textContent = label;
    b.addEventListener("click", () => { driveState.filter = value; renderDrive(); });
    return b;
  };
  chips.appendChild(mk("All files", null));
  driveState.folders.forEach((f) => chips.appendChild(mk(f, f)));

  const files = driveState.filter
    ? driveState.files.filter((f) => (f.folders || []).includes(driveState.filter))
    : driveState.files;

  const empty = $("dr-empty"), table = $("dr-table"), rows = $("dr-rows");
  if (!files.length) {
    table.classList.add("hidden");
    empty.classList.remove("hidden");
    if (driveState.filter) {
      empty.querySelector("strong").textContent = "No files in this folder.";
    }
  } else {
    empty.classList.add("hidden");
    table.classList.remove("hidden");
    rows.innerHTML = "";
    files.forEach((f) => rows.appendChild(fileRow(f)));
  }

  const errBox = $("dr-meta-errors");
  if (driveState.metaErrors && driveState.metaErrors.length) {
    errBox.textContent =
      `${driveState.metaErrors.length} file(s) could not be decrypted and are hidden.`;
    errBox.classList.remove("hidden");
  } else {
    errBox.classList.add("hidden");
  }
}

/* Outline icons per BRAND.md §5 — inline SVG, currentColor, 24×24 viewBox. */
const ICON_PATHS = {
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
  video: '<rect x="2" y="4" width="15" height="16" rx="2"/><path d="m22 8-5 4 5 4V8z"/>',
  audio: '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
  pdf: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
  text: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
};

function fileIcon(mime) {
  mime = mime || "";
  let key = "file";
  if (mime.startsWith("image/")) key = "image";
  else if (mime.startsWith("video/")) key = "video";
  else if (mime.startsWith("audio/")) key = "audio";
  else if (mime === "application/pdf") key = "pdf";
  else if (mime.startsWith("text/") || mime === "application/json") key = "text";
  const span = document.createElement("span");
  span.className = "file-icon";
  span.innerHTML =
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ` +
    `stroke-linecap="round" stroke-linejoin="round">${ICON_PATHS[key]}</svg>`;
  return span;
}

function fileRow(f) {
  const tr = document.createElement("tr");

  const name = document.createElement("td");
  const link = document.createElement("span");
  link.className = "file-name";
  link.title = "Preview";
  link.appendChild(fileIcon(f.mime_type));
  const fname = document.createElement("span");
  fname.className = "fname";
  fname.textContent = f.filename;
  link.appendChild(fname);
  link.addEventListener("click", () => previewFile(f));
  name.appendChild(link);

  const folder = document.createElement("td");
  folder.textContent = (f.folders || []).join(", ") || "—";
  folder.style.color = "var(--muted)";

  const size = document.createElement("td");
  size.textContent = fmtBytes(f.size_bytes);
  size.style.color = "var(--muted)";

  const date = document.createElement("td");
  date.textContent = fmtDate(f.created_at);
  date.style.color = "var(--muted)";

  const actions = document.createElement("td");
  actions.className = "file-actions";
  const dl = document.createElement("button");
  dl.className = "btn";
  dl.textContent = "Download";
  dl.addEventListener("click", () => downloadFile(f));
  const del = document.createElement("button");
  del.className = "btn danger-btn";
  del.textContent = "Delete";
  del.addEventListener("click", () => deleteFile(f));
  actions.append(dl, del);

  tr.append(name, folder, size, date, actions);
  return tr;
}

async function downloadFile(f) {
  try {
    const blobUrl = await fetchBlobUrl(
      `/admin/api/drive/file/${encodeURIComponent(f.post_cid)}?download=true`);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = f.filename || "file";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 30000);
  } catch (err) {
    toast("Download failed: " + err.message, true);
  }
}

async function previewFile(f) {
  const url = `/admin/api/drive/file/${encodeURIComponent(f.post_cid)}`;
  const mime = f.mime_type || "";
  const body = $("pv-body");
  body.innerHTML = "";
  $("pv-name").textContent = f.filename;
  $("pv-download").onclick = (e) => { e.preventDefault(); downloadFile(f); };
  $("pv-download").href = "#";

  try {
    if (mime.startsWith("image/")) {
      const img = document.createElement("img");
      img.src = await fetchBlobUrl(url); img.alt = f.filename;
      body.appendChild(img);
    } else if (mime.startsWith("video/")) {
      const v = document.createElement("video");
      v.src = await fetchBlobUrl(url); v.controls = true;
      body.appendChild(v);
    } else if (mime.startsWith("audio/")) {
      const a = document.createElement("audio");
      a.src = await fetchBlobUrl(url); a.controls = true;
      body.appendChild(a);
    } else if (mime === "application/pdf") {
      const fr = document.createElement("iframe");
      fr.src = await fetchBlobUrl(url);
      body.appendChild(fr);
    } else if (mime.startsWith("text/") || mime === "application/json") {
      const pre = document.createElement("pre");
      pre.textContent = "Loading…";
      body.appendChild(pre);
      fetch(url, { headers: authHeaders() }).then((r) => r.text()).then((t) => {
        pre.textContent = t.length > 200000 ? t.slice(0, 200000) + "\n… (truncated)" : t;
      }).catch((e) => { pre.textContent = "Could not load file: " + e.message; });
    } else {
      const p = document.createElement("div");
      p.className = "state-block";
      p.textContent = "No inline preview for this file type — use Download.";
      body.appendChild(p);
    }
  } catch (err) {
    const p = document.createElement("div");
    p.className = "state-block danger";
    p.textContent = "Could not load preview: " + err.message;
    body.appendChild(p);
  }
  $("preview").classList.remove("hidden");
}

$("pv-close").addEventListener("click", () => $("preview").classList.add("hidden"));
$("preview").addEventListener("click", (e) => {
  if (e.target === $("preview")) $("preview").classList.add("hidden");
});

async function deleteFile(f) {
  if (!confirm(`Delete "${f.filename}"?\n\nThis removes the post and its manifest entry, unpins the content from IPFS, and cannot be undone.`)) return;
  try {
    await postJson("/admin/api/drive/delete", { post_cid: f.post_cid });
    toast(`Deleted ${f.filename}`);
    loadDrive(true);
  } catch (err) {
    toast("Delete failed: " + err.message, true);
  }
}

/* ---- upload: picker + drag-drop, with folder dialog + progress ---- */
let pendingFiles = [];

$("dr-file-input").addEventListener("change", (e) => {
  if (e.target.files.length) askFolder([...e.target.files]);
  e.target.value = "";
});

const dz = $("dr-dropzone");
["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => {
  e.preventDefault(); dz.classList.add("dragover");
}));
["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => {
  e.preventDefault(); dz.classList.remove("dragover");
}));
dz.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) askFolder([...e.dataTransfer.files]);
});

function askFolder(files) {
  pendingFiles = files;
  $("fd-files").textContent =
    files.length === 1 ? files[0].name : `${files.length} files selected`;
  const list = $("fd-folder-list");
  list.innerHTML = "";
  driveState.folders.forEach((f) => {
    const o = document.createElement("option");
    o.value = f;
    list.appendChild(o);
  });
  $("fd-folder").value = driveState.filter || "";
  $("folder-dialog").classList.remove("hidden");
}

$("fd-cancel").addEventListener("click", () => {
  pendingFiles = [];
  $("folder-dialog").classList.add("hidden");
});

/* XHR (not fetch) for real upload progress events. */
function uploadWithProgress(file, folder, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/admin/api/drive/upload");
    xhr.setRequestHeader("Authorization", "Bearer " + TOKEN);
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total);
    });
    xhr.addEventListener("load", () => {
      if (xhr.status === 401) { showLogin(); reject(new Error("panel token required")); return; }
      if (xhr.status >= 200 && xhr.status < 300) { resolve(); return; }
      let detail = xhr.statusText;
      try { detail = JSON.parse(xhr.responseText).detail || detail; } catch (_) {}
      reject(new Error(detail));
    });
    xhr.addEventListener("error", () => reject(new Error("network error")));
    const fd = new FormData();
    fd.append("file", file);
    if (folder) fd.append("folder", folder);
    xhr.send(fd);
  });
}

$("fd-go").addEventListener("click", async () => {
  const folder = $("fd-folder").value.trim();
  const files = pendingFiles;
  pendingFiles = [];
  $("folder-dialog").classList.add("hidden");
  const box = $("dr-uploads");
  box.classList.remove("hidden");

  for (const file of files) {
    const row = document.createElement("div");
    row.className = "upload-row";
    row.innerHTML =
      `<span class="uname">${file.name.replace(/</g, "&lt;")}</span>` +
      `<span class="meter"><span class="meter-fill" style="display:block"></span></span>` +
      `<span class="status">0%</span>`;
    box.appendChild(row);
    const status = row.querySelector(".status");
    const fill = row.querySelector(".meter-fill");
    try {
      await uploadWithProgress(file, folder, (frac) => {
        const pct = Math.round(frac * 100);
        fill.style.width = pct + "%";
        status.textContent = pct < 100 ? pct + "%" : "encrypting…";
      });
      fill.style.width = "100%";
      status.textContent = "done";
    } catch (err) {
      status.textContent = "failed: " + err.message;
      status.classList.add("err");
    }
  }
  setTimeout(() => { box.innerHTML = ""; box.classList.add("hidden"); }, 4000);
  loadDrive(true);
});
