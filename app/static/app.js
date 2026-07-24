// Cipherlatch UI: profile menu, theme switch, copy/confirm helpers, and a
// dependency-free JSON/YAML code editor (highlight + error identification).

function currentTheme() {
  return (
    document.documentElement.dataset.theme ||
    (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
  );
}
function setTheme(next) {
  document.documentElement.dataset.theme = next;
  localStorage.setItem("cipherlatch-theme", next);
  const sw = document.getElementById("theme-switch");
  if (sw) sw.checked = next === "dark";
}

/* ── accent picker (per-user, persisted) ─────────────────────────────── */
const ACCENT_DEFAULT = "#3D3C49";
const ACCENT_SWATCHES = ["#3D3C49","#6d5efc","#06b6d4","#14b8a6","#22c55e",
                         "#eab308","#f97316","#ef4444","#ec4899","#a855f7"];
function applyAccent(hex, persist) {
  document.documentElement.style.setProperty("--accent", hex);
  if (persist) localStorage.setItem("cipherlatch-accent", hex);
  const cp = document.getElementById("accent-color");
  const hx = document.getElementById("accent-hex");
  if (cp) cp.value = hex;
  if (hx) hx.value = hex.toUpperCase();
  document.querySelectorAll("#accent-swatches .sw").forEach((s) =>
    s.setAttribute("aria-pressed", s.dataset.c.toLowerCase() === hex.toLowerCase() ? "true" : "false"));
}
function initAccentPicker() {
  const wrap = document.getElementById("accent-swatches");
  if (!wrap) return;
  ACCENT_SWATCHES.forEach((c) => {
    const b = document.createElement("button");
    b.type = "button"; b.className = "sw"; b.dataset.c = c; b.style.background = c;
    b.setAttribute("aria-label", "Accent " + c);
    b.addEventListener("click", () => applyAccent(c, true));
    wrap.appendChild(b);
  });
  const cp = document.getElementById("accent-color");
  const hx = document.getElementById("accent-hex");
  const reset = document.getElementById("accent-reset");
  if (cp) cp.addEventListener("input", (e) => applyAccent(e.target.value, true));
  if (hx) hx.addEventListener("change", (e) => {
    if (/^#[0-9a-f]{6}$/i.test(e.target.value)) applyAccent(e.target.value, true);
  });
  if (reset) reset.addEventListener("click", () => {
    localStorage.removeItem("cipherlatch-accent"); applyAccent(ACCENT_DEFAULT, false);
  });
  applyAccent(localStorage.getItem("cipherlatch-accent") || ACCENT_DEFAULT, false);
}

document.addEventListener("DOMContentLoaded", () => {
  // profile dropdown
  const pbtn = document.getElementById("profile-btn");
  const menu = document.getElementById("profile-menu");
  if (pbtn && menu) {
    const close = () => { menu.hidden = true; pbtn.setAttribute("aria-expanded", "false"); };
    pbtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = menu.hidden;
      menu.hidden = !open;
      pbtn.setAttribute("aria-expanded", String(open));
    });
    menu.addEventListener("click", (e) => e.stopPropagation());
    document.addEventListener("click", close);
    document.addEventListener("keydown", (e) => e.key === "Escape" && close());
  }

  // theme switch (reflects current theme, flips it)
  const sw = document.getElementById("theme-switch");
  if (sw) {
    sw.checked = currentTheme() === "dark";
    sw.addEventListener("change", () => setTheme(sw.checked ? "dark" : "light"));
  }

  // accent picker (per-user, persisted; applied before-paint in base.html)
  initAccentPicker();

  // instant client-side filter for list pages: <input data-filter="#tbody">
  // hides non-matching rows and updates an optional [data-filter-count].
  document.querySelectorAll("input[data-filter]").forEach((inp) => {
    const body = document.querySelector(inp.dataset.filter);
    if (!body) return;
    const counter = inp.dataset.filterCount ? document.querySelector(inp.dataset.filterCount) : null;
    const rows = [...body.querySelectorAll("tr")];
    const total = rows.length;
    const noun = inp.dataset.filterNoun || "rows";
    inp.addEventListener("input", () => {
      const q = inp.value.trim().toLowerCase();
      let shown = 0;
      rows.forEach((r) => {
        const hit = !q || r.textContent.toLowerCase().includes(q);
        r.hidden = !hit;
        if (hit) shown++;
      });
      if (counter) counter.textContent = q ? `${shown} of ${total} ${noun}` : `${total} ${noun}`;
    });
  });

  // Focus-mode editing: opening a create/edit panel veils the rest of the
  // page and elevates the panel. Esc or a click on the veil closes it.
  let veilEl = null, focusEl = null;
  const closeFocus = () => {
    if (veilEl) { veilEl.remove(); veilEl = null; }
    if (focusEl) {
      focusEl.classList.add("hidden");
      focusEl.classList.remove("focus-open");
      focusEl = null;
    }
  };
  const openFocus = (t) => {
    closeFocus();
    t.classList.remove("hidden");
    t.classList.add("focus-open");
    veilEl = document.createElement("div");
    veilEl.className = "veil";
    veilEl.addEventListener("click", closeFocus);
    document.body.appendChild(veilEl);
    focusEl = t;
    t.scrollIntoView({ block: "nearest" });
    const f = t.querySelector("input:not([type=hidden]):not([type=checkbox]), select, textarea");
    if (f) f.focus();
  };
  document.querySelectorAll("[data-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const t = document.querySelector(btn.dataset.toggle);
      if (!t) return;
      if (t.classList.contains("hidden")) openFocus(t); else closeFocus();
    });
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeFocus(); });

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const el = document.querySelector(btn.dataset.copy);
      if (!el) return;
      await navigator.clipboard.writeText(el.textContent.trim());
      const old = btn.textContent;
      btn.textContent = "copied ✓";
      setTimeout(() => (btn.textContent = old), 1200);
    });
  });

  document.querySelectorAll("[data-confirm]").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (el.dataset._ok) { delete el.dataset._ok; return; }   // let the re-fire through
      const key = confirmKey(el);
      if (localStorage.getItem("cipherlatch-confirm-skip:" + key) === "1") return;
      e.preventDefault();
      showConfirm(el.dataset.confirm, key, () => { el.dataset._ok = "1"; el.click(); });
    });
  });

  // fill any copy-as-curl snippet from the live origin (so it works on any host)
  document.querySelectorAll("[data-curl-cid]").forEach((el) => {
    el.textContent =
      `curl -s ${location.origin}/oauth/token ` +
      `-d grant_type=client_credentials ` +
      `-d client_id=${el.dataset.curlCid} -d client_secret=$CLIENT_SECRET`;
  });
  // fill any element that wants the live JWKS URL
  document.querySelectorAll("[data-jwks-url]").forEach((el) => {
    el.textContent = `${location.origin}/.well-known/jwks.json`;
  });

  // profile photo: resize client-side to a small square data URI, then submit
  const avUpload = document.getElementById("avatar-upload");
  const avFile = document.getElementById("avatar-file");
  const avForm = document.getElementById("avatar-form");
  const avData = document.getElementById("avatar-data");
  if (avUpload && avFile && avForm && avData) {
    avUpload.addEventListener("click", () => avFile.click());
    avFile.addEventListener("change", () => {
      const f = avFile.files[0];
      if (!f) return;
      // data: URL via FileReader — a blob: URL is blocked by the CSP.
      const reader = new FileReader();
      reader.onload = () => {
        const img = new Image();
        img.onload = () => {
          const S = 128, c = document.createElement("canvas");
          c.width = c.height = S;
          const ctx = c.getContext("2d");
          const s = Math.min(img.width, img.height);           // cover-crop to square
          ctx.drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, S, S);
          avData.value = c.toDataURL("image/jpeg", 0.85);
          avForm.submit();
        };
        img.onerror = () => alert("That file could not be read as an image.");
        img.src = reader.result;
      };
      reader.onerror = () => alert("That file could not be read as an image.");
      reader.readAsDataURL(f);
    });
  }

  // upgrade any <textarea data-code="json|yaml"> into a code editor
  document.querySelectorAll("textarea[data-code]").forEach(makeCodeEditor);
});

/* ── confirm modal (consequence + "don't show again") ────────────────── */
// Suppression is keyed per operation: the last path segment of the button's
// form action (rotate / revoke / revoke-grant / delete / ...), or an explicit
// data-confirm-key.
function confirmKey(el) {
  if (el.dataset.confirmKey) return el.dataset.confirmKey;
  const action = el.form ? el.form.getAttribute("action") : el.getAttribute("href");
  if (action) return action.replace(/\/+$/, "").split("/").pop().split("?")[0];
  return "generic";
}
function showConfirm(message, key, onConfirm) {
  const back = document.createElement("div");
  back.className = "modal-backdrop";
  back.innerHTML =
    '<div class="modal" role="dialog" aria-modal="true">' +
    '<h3>Please confirm</h3><p></p>' +
    '<label class="dsa"><input type="checkbox"> Don’t ask again for this action</label>' +
    '<div class="modal-actions">' +
    '<button class="btn" data-x>Cancel</button>' +
    '<button class="btn btn-primary" data-go>Confirm</button></div></div>';
  back.querySelector("p").textContent = message;
  document.body.appendChild(back);
  const dsa = back.querySelector(".dsa input");
  const close = () => back.remove();
  back.querySelector("[data-go]").focus();
  back.addEventListener("click", (e) => { if (e.target === back) close(); });
  back.querySelector("[data-x]").addEventListener("click", close);
  document.addEventListener("keydown", function esc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
  });
  back.querySelector("[data-go]").addEventListener("click", () => {
    if (dsa.checked) localStorage.setItem("cipherlatch-confirm-skip:" + key, "1");
    close();
    onConfirm();
  });
}

/* ── code editor ─────────────────────────────────────────────────────── */
const esc = (s) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

// Regex highlighters returning HTML with token spans, per line so the error
// line can be boxed.
function highlightJSON(src) {
  return esc(src).replace(
    /("(?:\\.|[^"\\])*"(\s*:)?)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(true|false)|(null)|([{}\[\],:])/g,
    (m, str, colon, num, bool, nul, punct) => {
      if (str) return `<span class="${colon ? "tok-key" : "tok-str"}">${str}</span>`;
      if (num) return `<span class="tok-num">${num}</span>`;
      if (bool) return `<span class="tok-bool">${bool}</span>`;
      if (nul) return `<span class="tok-null">${nul}</span>`;
      if (punct) return `<span class="tok-punct">${punct}</span>`;
      return m;
    }
  );
}
function highlightYAML(line) {
  if (/^\s*#/.test(line)) return `<span class="tok-com">${esc(line)}</span>`;
  let out = esc(line);
  out = out.replace(/(#.*)$/, '<span class="tok-com">$1</span>');
  out = out.replace(
    /^(\s*(?:-\s*)?)([\w.$-]+)(\s*:)(\s|$)/,
    '$1<span class="tok-key">$2</span><span class="tok-punct">$3</span>$4'
  );
  out = out.replace(/\b(true|false|null|yes|no)\b/gi, '<span class="tok-bool">$1</span>');
  return out;
}

// Validators -> {ok:true} | {ok:false, line, msg}.
function validateJSON(src) {
  if (!src.trim()) return { ok: true };
  try {
    JSON.parse(src);
    return { ok: true };
  } catch (e) {
    const raw = e.message;
    // The message shape differs per engine and the newer V8 form embeds a
    // source snippet (starting at the first double-quote). Cut it there, then
    // trim the trailing "in JSON…/is not valid JSON/at line…" boilerplate.
    const q = raw.indexOf('"');
    let short = (q > 0 ? raw.slice(0, q) : raw)
      .replace(/ (?:in JSON.*|at line.*|of the JSON.*|is not valid JSON.*)/, "")
      .replace(/[\s,]*(?:\.\.\.)?[\s,]*$/, "")
      .trim();
    let pos = null, m;
    if ((m = /position (\d+)/.exec(raw))) pos = +m[1]; // Chrome (older), Node
    else if ((m = /line (\d+) column (\d+)/.exec(raw))) // Firefox
      return { ok: false, line: +m[1], msg: short };
    else if ((m = /"((?:[^"\\]|\\.)*)" is not valid JSON/.exec(raw))) {
      // Chrome (newer): error message quotes a snippet around the fault.
      let snip = m[1].replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
      snip = snip.replace(/^\.\.\./, "").replace(/\.\.\.$/, "");
      const idx = src.indexOf(snip);
      if (idx >= 0) pos = idx + Math.max(0, snip.search(/[,:\[\]{}]/));
    }
    const line = pos == null ? 1 : src.slice(0, pos).split("\n").length;
    return { ok: false, line, msg: short };
  }
}
function validateYAML(src) {
  // Dependency-free structural check (not a full parser): the mistake people
  // actually make — a tab in the indentation.
  if (!src.trim()) return { ok: true };
  const lines = src.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (/^ *\t/.test(lines[i]))
      return { ok: false, line: i + 1, msg: "YAML forbids tabs for indentation" };
  }
  return { ok: true };
}

function makeCodeEditor(ta) {
  const lang = ta.dataset.code === "yaml" ? "yaml" : "json";
  const hlLine = lang === "yaml" ? highlightYAML : (l) => highlightJSON(l);
  const validate = lang === "yaml" ? validateYAML : validateJSON;

  const wrap = document.createElement("div");
  wrap.className = "code-editor";
  const scroll = document.createElement("div");
  scroll.className = "ce-scroll";
  const gutter = document.createElement("div");
  gutter.className = "ce-gutter";
  const pre = document.createElement("pre");
  pre.className = "ce-hl";
  pre.setAttribute("aria-hidden", "true");
  const code = document.createElement("code");
  pre.appendChild(code);
  const status = document.createElement("div");
  status.className = "ce-status";

  ta.parentNode.insertBefore(wrap, ta);
  ta.classList.add("ce-input");
  ta.spellcheck = false;
  ta.setAttribute("autocomplete", "off");
  ta.setAttribute("autocapitalize", "off");
  scroll.append(gutter, pre, ta);
  wrap.append(scroll);
  wrap.after(status);

  const render = () => {
    const src = ta.value;
    const res = validate(src);
    const lines = src.split("\n");
    gutter.innerHTML = lines
      .map((_, i) => `<div class="ln${!res.ok && res.line === i + 1 ? " err" : ""}">${i + 1}</div>`)
      .join("");
    code.innerHTML = lines
      .map((ln, i) => {
        const html = hlLine(ln) || "​";
        const err = !res.ok && res.line === i + 1 ? " err" : "";
        return `<span class="line${err}">${html}</span>`;
      })
      .join("\n");
    wrap.classList.toggle("ok", res.ok && src.trim() !== "");
    wrap.classList.toggle("bad", !res.ok);
    status.className = "ce-status " + (src.trim() === "" ? "" : res.ok ? "ok" : "bad");
    status.textContent = src.trim() === ""
      ? ""
      : res.ok
      ? `✓ valid ${lang.toUpperCase()}`
      : `✗ line ${res.line}: ${res.msg}`;
  };

  const syncScroll = () => {
    pre.scrollTop = ta.scrollTop;
    pre.scrollLeft = ta.scrollLeft;
    gutter.scrollTop = ta.scrollTop;
  };
  ta.addEventListener("input", render);
  ta.addEventListener("scroll", syncScroll);
  ta.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const s = ta.selectionStart, en = ta.selectionEnd;
      ta.value = ta.value.slice(0, s) + "  " + ta.value.slice(en);
      ta.selectionStart = ta.selectionEnd = s + 2;
      render();
    }
  });
  render();
}

// Route template picker: pre-fill the create-route form from the catalog.
document.addEventListener("DOMContentLoaded", () => {
  const picker = document.getElementById("route-template");
  const dataEl = document.getElementById("route-catalog-data");
  const form = document.getElementById("create-route");
  if (!picker || !dataEl || !form) return;
  let catalog = [];
  try { catalog = JSON.parse(dataEl.textContent); } catch (e) { return; }
  const hint = document.getElementById("route-template-hint");
  const set = (name, val) => {
    const el = form.querySelector(`[name="${name}"]`);
    if (el != null && val != null) el.value = val;
  };
  const check = (name, on) => {
    const el = form.querySelector(`[name="${name}"]`);
    if (el) el.checked = !!on;
  };
  picker.addEventListener("change", () => {
    const c = catalog.find((x) => x.id === picker.value);
    if (!c) { if (hint) hint.textContent = ""; return; }
    const slugEl = form.querySelector('[name="slug"]');
    // fill/refresh the slug on each pick, but never clobber one the user typed
    if (slugEl && (!slugEl.value || slugEl.value === picker.dataset.autoSlug)) {
      slugEl.value = c.id;
      picker.dataset.autoSlug = c.id;
    }
    set("upstream_base", c.upstream);
    set("inject_mode", c.inject_mode);
    set("inject_header", c.inject_header);
    set("methods", (c.methods || []).join(" "));
    // Leave `icon` empty: create-time autodiscovery then fetches the real
    // favicon from the vendor's own server (nothing trademarked ships here).
    set("icon", "");
    check("git_http", c.git_http);
    check("skip_tls_verify", !c.verify_tls);
    if (hint) {
      const bits = [];
      if (c.needs_host) bits.push("Replace {host} in the upstream URL.");
      if (c.cred_hint) bits.push("Credential: " + c.cred_hint);
      if (c.test_path) bits.push("Test path: " + c.test_path);
      if (c.note) bits.push("⚠ " + c.note);
      hint.textContent = bits.join("   ·   ");
    }
  });
});

/* ── icon dialog (shared by agents, credentials, routes) ─────────────── */
// Openers carry data-icon-post (edit: POST immediately) or data-icon-stage
// (create forms: fill the form's hidden icon/icon_upload fields). The dialog
// itself lives in a <template> included once per page (_icon_dialog.html).
document.addEventListener("DOMContentLoaded", () => {
  const tpl = document.getElementById("icon-dialog-tpl");
  if (!tpl) return;
  const EMOJI = ["🤖", "🔧", "🔑", "🦊", "🐙", "🏠", "📦", "☁️", "🛰️", "🗄️"];

  const resize = (file, cb) => {
    // Read via FileReader → a data: URL. A blob: URL (URL.createObjectURL)
    // would be refused by the page CSP (img-src 'self' data:), so the <img>
    // would never load and the upload would silently fail.
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const S = 64, c = document.createElement("canvas");
        c.width = c.height = S;
        const ctx = c.getContext("2d");
        const s = Math.min(img.width, img.height); // cover-crop to square
        ctx.drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, S, S);
        cb(c.toDataURL("image/png"));
      };
      img.onerror = () => cb(null);
      img.src = reader.result;
    };
    reader.onerror = () => cb(null);
    reader.readAsDataURL(file);
  };

  const postForm = (action, fields) => {
    const f = document.createElement("form");
    f.method = "post";
    f.action = action;
    for (const [k, v] of Object.entries(fields)) {
      const i = document.createElement("input");
      i.type = "hidden"; i.name = k; i.value = v;
      f.appendChild(i);
    }
    document.body.appendChild(f);
    f.submit();
  };

  document.querySelectorAll(".icon-open").forEach((opener) => {
    opener.addEventListener("click", () => {
      const frag = tpl.content.cloneNode(true);
      const back = frag.querySelector(".icon-backdrop");
      document.body.appendChild(frag);
      const q = (sel) => back.querySelector(sel);
      const stageSel = opener.dataset.iconStage || "";
      const postUrl = opener.dataset.iconPost || "";
      let tab = "url";
      let uploadData = "";

      q(".icon-for").textContent = "— " + (opener.dataset.iconFor || "");
      if (opener.dataset.iconDetect && postUrl) q(".icon-detect").classList.remove("hidden");
      const emojiInput = q('[name="emoji"]');
      emojiInput.value = opener.dataset.iconCurrent || "";
      if (!opener.dataset.iconHas && !stageSel) q(".icon-remove").classList.add("hidden");
      if (stageSel) q(".icon-remove").textContent = "Clear choice";

      const preview = q(".icon-box"), note = q(".icon-note");
      const setPreview = (content, msg) => {
        preview.innerHTML = "";
        if (content instanceof Element) preview.appendChild(content);
        else preview.textContent = content || "";
        note.textContent = msg || "";
      };

      EMOJI.forEach((e) => {
        const b = document.createElement("button");
        b.type = "button"; b.textContent = e;
        b.addEventListener("click", () => { emojiInput.value = e; setPreview(e, ""); });
        q(".emoji-quick").appendChild(b);
      });

      back.querySelectorAll("[role=tab]").forEach((t) => {
        t.addEventListener("click", () => {
          back.querySelectorAll("[role=tab]").forEach((x) => x.setAttribute("aria-selected", "false"));
          t.setAttribute("aria-selected", "true");
          tab = t.dataset.pane;
          back.querySelectorAll(".icon-pane").forEach((pane) =>
            pane.classList.toggle("hidden", pane.dataset.pane !== tab));
        });
      });

      const file = q(".icon-file");
      q(".icon-browse").addEventListener("click", () => file.click());
      file.addEventListener("change", () => {
        const f = file.files[0];
        if (!f) return;
        resize(f, (data) => {
          if (!data) { q(".icon-upload-info").textContent = "That file could not be read as an image."; return; }
          uploadData = data;
          q(".icon-upload-info").textContent = f.name + " → 64 px";
          const img = document.createElement("img");
          img.src = data; img.width = 20; img.height = 20;
          setPreview(img, "ready to save");
        });
      });

      const close = () => back.remove();
      back.addEventListener("click", (e) => { if (e.target === back) close(); });
      q(".icon-cancel").addEventListener("click", close);
      document.addEventListener("keydown", function esc(e) {
        if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
      });

      const stage = (icon, upload, previewMsg) => {
        const form = document.querySelector(stageSel);
        if (!form) return;
        form.querySelector('[name="icon"]').value = icon;
        form.querySelector('[name="icon_upload"]').value = upload;
        const sp = form.querySelector(".icon-stage-preview");
        if (sp) sp.textContent = previewMsg;
      };

      q(".icon-detect").addEventListener("click", () => {
        postForm(postUrl, { mode: "detect" });
      });
      q(".icon-remove").addEventListener("click", () => {
        if (stageSel) { stage("", "", "auto-detect / none"); close(); return; }
        postForm(postUrl, { mode: "remove" });
      });
      q(".icon-save").addEventListener("click", () => {
        let mode = tab, value = "", data = "";
        if (tab === "url") {
          value = q('[name="url"]').value.trim();
          if (!value) { note.textContent = "Enter an image URL first."; return; }
        } else if (tab === "upload") {
          if (!uploadData) { note.textContent = "Choose an image first."; return; }
          data = uploadData;
        } else {
          mode = "emoji";
          value = emojiInput.value.trim();
          if (!value) { note.textContent = "Enter or pick an emoji first."; return; }
        }
        if (stageSel) {
          if (mode === "upload") stage("", data, "uploaded image (64 px)");
          else stage(value, "", mode === "url" ? "fetched from URL on create" : value);
          close();
          return;
        }
        postForm(postUrl, { mode: mode, value: value, data: data });
      });
    });
  });
});

/* ── access map: dependency-free static sankey ───────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  const holder = document.getElementById("access-map");
  const dataEl = document.getElementById("access-map-data");
  if (!holder || !dataEl) return;
  let g;
  try { g = JSON.parse(dataEl.textContent); } catch (e) { return; }

  const NS = "http://www.w3.org/2000/svg";
  const W = 960, NW = 170, TOP = 30, GAP = 18, MINH = 34;
  const cols = [
    { key: "agents", x: 4, head: "AGENTS" },
    { key: "routes", x: (W - NW) / 2, head: "ROUTES" },
    { key: "credentials", x: W - NW - 4, head: "CREDENTIALS" },
  ];
  const links = [
    ...g.links_ar.map((l) => ({ ...l, x0: cols[0].x + NW, x1: cols[1].x })),
    ...g.links_rc.map((l) => ({ ...l, x0: cols[1].x + NW, x1: cols[2].x })),
    ...g.direct.map((l) => ({ ...l, x0: cols[0].x + NW, x1: cols[2].x, direct: true })),
  ];
  // Baseline weight so a grant with no traffic still shows.
  links.forEach((l) => { l.v = (l.w || 0) + 1; });

  const byId = {};
  cols.forEach((c) => g[c.key].forEach((n) => {
    n.vin = 0; n.vout = 0; byId[n.id] = n;
  }));
  links.forEach((l) => { byId[l.from].vout += l.v; byId[l.to].vin += l.v; });
  // Node height follows its busier side (in and out each span the full node).
  cols.forEach((c) => g[c.key].forEach((n) => { n.total = Math.max(n.vin, n.vout); }));
  // Only show nodes that participate in at least one edge.
  cols.forEach((c) => { g[c.key] = g[c.key].filter((n) => n.total > 0); });

  // Scale: the busiest column fits in ~420px of ribbon.
  const colTotal = (c) => g[c.key].reduce((a, n) => a + n.total, 0);
  const maxTotal = Math.max(1, ...cols.map(colTotal));
  const S = Math.min(3, 420 / maxTotal);

  let H = TOP + 20;
  cols.forEach((c) => {
    const nodes = g[c.key];
    let h = TOP + 10;
    nodes.forEach((n) => { n.h = Math.max(MINH, n.total * S); h += n.h + GAP; });
    H = Math.max(H, h);
  });
  cols.forEach((c) => {
    const nodes = g[c.key];
    const total = nodes.reduce((a, n) => a + n.h, 0) + GAP * Math.max(0, nodes.length - 1);
    let y = TOP + (H - TOP - total) / 2;
    nodes.forEach((n) => { n.y = y; n.outY = y; n.inY = y; y += n.h + GAP; });
  });

  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 " + W + " " + H);
  svg.setAttribute("id", "sankey");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Access map: agents to routes to credentials");
  const el = (tag, attrs, parent) => {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    (parent || svg).appendChild(e);
    return e;
  };

  cols.forEach((c) => {
    el("text", { x: c.x + NW / 2, y: 14, "text-anchor": "middle", "class": "colhead" })
      .textContent = c.head;
  });

  const linkEls = [];
  links.forEach((l) => {
    const a = byId[l.from], b = byId[l.to];
    if (!a || !b) return;
    const wA = a.h * (l.v / a.vout), wB = b.h * (l.v / b.vin);
    const y0 = a.outY, y1 = b.inY;
    a.outY += wA; b.inY += wB;
    const xm = (l.x0 + l.x1) / 2;
    const d = "M" + l.x0 + "," + y0 +
      " C" + xm + "," + y0 + " " + xm + "," + y1 + " " + l.x1 + "," + y1 +
      " L" + l.x1 + "," + (y1 + wB) +
      " C" + xm + "," + (y1 + wB) + " " + xm + "," + (y0 + wA) + " " + l.x0 + "," + (y0 + wA) + " Z";
    const path = el("path", { d: d, "class": "link" + (l.direct ? " direct" : "") });
    path._from = l.from; path._to = l.to;
    const t = el("title", {}, path);
    t.textContent = a.label + " → " + b.label +
      (l.w ? " · " + l.w + " requests / " + g.window_days + "d" : " · no traffic yet") +
      (l.direct ? " · direct exchange" : "");
    if (l.direct) {
      el("path", {
        d: "M" + l.x0 + "," + (y0 + wA / 2) +
          " C" + xm + "," + (y0 + wA / 2) + " " + xm + "," + (y1 + wB / 2) + " " + l.x1 + "," + (y1 + wB / 2),
        "class": "direct-line",
      });
    }
    linkEls.push(path);
  });

  const trunc = (t, n) => (t.length > n ? t.slice(0, n - 1) + "…" : t);
  cols.forEach((c) => g[c.key].forEach((n) => {
    el("rect", { x: c.x, y: n.y, width: NW, height: n.h, "class": "node-rect", "data-node": n.id });
    const two = n.h >= 46;
    const hasImg = (n.icon || "").startsWith("data:");
    const tx = c.x + (hasImg ? 30 : 10);
    if (hasImg) {
      el("image", { href: n.icon, x: c.x + 8, y: n.y + n.h / 2 - 8, width: 16, height: 16,
                    "data-node": n.id, preserveAspectRatio: "xMidYMid meet" });
    }
    const label = (hasImg ? "" : (n.icon ? n.icon + " " : "")) + n.label;
    const t1 = el("text", { x: tx, y: n.y + (two ? n.h / 2 - 3 : n.h / 2 + 4.5),
                            "class": "node-name", "data-node": n.id });
    t1.textContent = trunc(label, hasImg ? 18 : 20);
    if (two) {
      const total = links.filter((l) => l.from === n.id || l.to === n.id)
        .reduce((a, l) => a + (l.w || 0), 0);
      const t2 = el("text", { x: tx, y: n.y + n.h / 2 + 13, "class": "node-count", "data-node": n.id });
      t2.textContent = total ? total + " requests · " + g.window_days + "d" : "no traffic yet";
    }
  }));

  const trace = (nodeId) => {
    const lit = {};
    linkEls.forEach((p) => { if (p._from === nodeId || p._to === nodeId) lit[p._from + ">" + p._to] = 1; });
    linkEls.forEach((p) => {
      if (lit[p._from + ">" + p._to]) {
        linkEls.forEach((q2) => {
          if (q2._from === p._to || q2._to === p._from) lit[q2._from + ">" + q2._to] = 1;
        });
      }
    });
    svg.classList.add("dimming");
    linkEls.forEach((p) => p.classList.toggle("lit", !!lit[p._from + ">" + p._to]));
  };
  svg.addEventListener("mouseover", (e) => {
    const n = e.target.getAttribute && e.target.getAttribute("data-node");
    if (n) trace(n);
  });
  svg.addEventListener("mouseout", (e) => {
    if (e.target.getAttribute && e.target.getAttribute("data-node")) {
      svg.classList.remove("dimming");
      linkEls.forEach((p) => p.classList.remove("lit"));
    }
  });

  holder.appendChild(svg);
});
