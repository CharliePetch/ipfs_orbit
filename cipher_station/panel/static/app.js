/* Cipher Station admin panel — vanilla JS, no build step. */
"use strict";

const $ = (id) => document.getElementById(id);

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
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
};

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

    $("d-status").textContent = "Running";
    $("d-version").textContent = (s.version || "?") + (s.commit ? ` (${s.commit})` : "");
    $("d-uptime").textContent = fmtUptime(s.uptime_seconds);
    $("d-uid").textContent = s.uid || "—";
    $("d-endpoint").textContent = s.endpoint || "(not published yet)";
    $("d-peer").textContent = s.peer_id || "(unknown)";
    $("d-ipns").textContent = s.ipns_name || "(unknown)";

    const ipfs = s.ipfs || {};
    $("d-ipfs-status").textContent = ipfs.running ? "Running" : "Down";
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
    $("c-permurl").value = c.permanent_url || "";
    $("c-storage").value = c.ipfs_storage_max || "";
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
    await api("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alias: $("c-alias").value }),
    });
    await api("/admin/api/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        display_name: $("c-display").value,
        username: $("c-username").value,
        bio: $("c-bio").value,
        link: $("c-link").value,
      }),
    });
    setMsg("c-profile-msg", "Saved.");
  } catch (err) {
    setMsg("c-profile-msg", err.message, true);
  }
});

$("c-save-net").addEventListener("click", async () => {
  const url = $("c-permurl").value.trim();
  try {
    const body = { cloudflare_tunnel_enabled: $("c-tunnel").checked };
    if (url) body.permanent_url = url; else body.clear_permanent_url = true;
    const res = await api("/admin/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    setMsg("c-net-msg", "Saved.");
    if (res.restart_required) {
      $("c-restart-cmd").textContent = res.restart_command || "sudo systemctl restart cipherstation";
      $("c-restart-note").classList.remove("hidden");
    }
  } catch (err) {
    setMsg("c-net-msg", err.message, true);
  }
});

$("c-save-storage").addEventListener("click", async () => {
  try {
    await api("/admin/api/config/storage-max", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ storage_max: $("c-storage").value }),
    });
    setMsg("c-storage-msg", "Saved.");
    $("c-storage-restart").classList.remove("hidden");
  } catch (err) {
    setMsg("c-storage-msg", err.message, true);
  }
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

function fileRow(f) {
  const tr = document.createElement("tr");

  const name = document.createElement("td");
  const link = document.createElement("span");
  link.className = "file-name";
  link.textContent = f.filename;
  link.title = "Preview";
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
    await api("/admin/api/drive/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ post_cid: f.post_cid }),
    });
    toast(`Deleted ${f.filename}`);
    loadDrive(true);
  } catch (err) {
    toast("Delete failed: " + err.message, true);
  }
}

/* ---- upload: picker + drag-drop, with folder dialog ---- */
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
    row.innerHTML = `<span>${file.name}</span><span class="status">encrypting &amp; uploading…</span>`;
    box.appendChild(row);
    const status = row.querySelector(".status");
    try {
      const fd = new FormData();
      fd.append("file", file);
      if (folder) fd.append("folder", folder);
      await api("/admin/api/drive/upload", { method: "POST", body: fd });
      status.textContent = "done";
    } catch (err) {
      status.textContent = "failed: " + err.message;
      status.classList.add("err");
    }
  }
  setTimeout(() => { box.innerHTML = ""; box.classList.add("hidden"); }, 4000);
  loadDrive(true);
});
