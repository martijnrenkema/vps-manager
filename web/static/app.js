/* VPS Manager - shared front-end helpers.
 *
 * Loaded as a classic (non-deferred) script from base.html, right before the
 * page-specific scripts, so everything declared here is a global that inline
 * onclick handlers and page scripts can call at parse time.
 *
 * Server-side values arrive through window.VPS_CONFIG (inline JSON in base.html)
 * and the csrf-token <meta> tag.
 */

const VPS = window.VPS_CONFIG || {};
const csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

/* ------------------------------------------------------------------------ *
 * Global fetch wrapper
 *  - same-origin requests get X-Requested-With (so the server answers 401 JSON
 *    instead of redirecting to /login) and, for non-GET, X-CSRFToken
 *  - 401 {login_url}  -> redirect to the login page
 *  - 400 {csrf_expired} -> explain that the page must be reloaded
 * EventSource (updates page) does not go through fetch and is unaffected.
 * ------------------------------------------------------------------------ */
(function installFetchWrapper() {
    if (!window.fetch || window.fetch.__vpsWrapped) return;
    const nativeFetch = window.fetch.bind(window);
    let redirecting = false;
    let csrfToastShown = false;

    function isSameOrigin(input) {
        try {
            const raw = (typeof input === 'string') ? input
                : (input instanceof URL) ? input.href
                : (input && input.url) || '';
            return new URL(raw, location.href).origin === location.origin;
        } catch (e) {
            return false;
        }
    }

    const wrapped = async function (input, init) {
        const sameOrigin = isSameOrigin(input);
        if (sameOrigin) {
            init = Object.assign({}, init || {});
            const isRequest = (typeof Request !== 'undefined') && (input instanceof Request);
            const method = String(init.method || (isRequest ? input.method : 'GET')).toUpperCase();
            const headers = new Headers(init.headers || (isRequest ? input.headers : undefined));
            if (!headers.has('X-Requested-With')) headers.set('X-Requested-With', 'XMLHttpRequest');
            if (method !== 'GET' && method !== 'HEAD' && !headers.has('X-CSRFToken') && csrfToken) {
                headers.set('X-CSRFToken', csrfToken);
            }
            init.headers = headers;
        }

        const res = await nativeFetch(input, init);

        if (sameOrigin && (res.status === 401 || res.status === 400)) {
            const ct = res.headers.get('content-type') || '';
            if (ct.indexOf('application/json') !== -1) {
                try {
                    const data = await res.clone().json();
                    if (res.status === 401 && data && data.login_url && !redirecting) {
                        redirecting = true;
                        showToast('Your session has ended. Redirecting to login…', 'warning');
                        setTimeout(function () { location.href = data.login_url; }, 600);
                    } else if (data && data.csrf_expired && !csrfToastShown) {
                        csrfToastShown = true;
                        showToast('Session security token expired — reload the page', 'error', {
                            duration: 15000,
                            action: { label: 'Reload', onClick: function () { location.reload(); } },
                            onClose: function () { csrfToastShown = false; },
                        });
                    }
                } catch (e) { /* not JSON after all */ }
            }
        }
        return res;
    };
    wrapped.__vpsWrapped = true;
    window.fetch = wrapped;
})();

/* Is this response one the global wrapper already explained to the user? */
function isAuthOrCsrfFailure(res, data) {
    return !!(res && data && ((res.status === 401 && data.login_url) || data.csrf_expired));
}

// Logout via a CSRF-protected POST (a GET link could be abused via <img src>
// to force someone out).
function doLogout() {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/logout';
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'csrf_token';
    input.value = csrfToken;
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
}

// HTML escaping helper. Also escapes quotes so it is safe inside a quoted
// attribute value (title="..."). NOTE: it does NOT make a value safe inside a
// JS string inside an event-handler attribute (onclick="f('...')"), because
// the browser decodes entities before the JS runs. For those, put the value in
// a data-* attribute and read it with this.dataset.
function escHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/* ------------------------------------------------------------------------ *
 * Toasts
 * showToast(message, type = 'success', opts = {duration, action:{label,onClick}})
 * ------------------------------------------------------------------------ */
const TOAST_ICONS = { success: '✓', info: 'i', warning: '!', error: '✕' };
const TOAST_DURATION = { success: 4000, info: 4500, warning: 6500, error: 8000 };

function showToast(message, type, opts) {
    type = type || 'success';
    opts = opts || {};
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const text = String(message == null ? '' : message);
    const toast = document.createElement('div');
    // 'show' matters: bootstrap.min.css hides any `.toast:not(.show)`.
    toast.className = 'toast show ' + type;
    if (type === 'error') toast.setAttribute('role', 'alert');

    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = TOAST_ICONS[type] || TOAST_ICONS.info;
    toast.appendChild(icon);

    const body = document.createElement('span');
    body.className = 'toast-msg';
    body.textContent = text;
    toast.appendChild(body);

    let timer = null;
    let closed = false;
    function close() {
        if (closed) return;
        closed = true;
        clearTimeout(timer);
        toast.classList.add('leaving');
        setTimeout(function () { toast.remove(); }, 200);
        if (typeof opts.onClose === 'function') opts.onClose();
    }

    if (opts.action && opts.action.label) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-sm';
        btn.style.marginLeft = '4px';
        btn.textContent = opts.action.label;
        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            close();
            opts.action.onClick && opts.action.onClick();
        });
        toast.appendChild(btn);
    }

    toast.title = 'Click to dismiss';
    toast.addEventListener('click', close);
    container.appendChild(toast);

    // Long messages (e.g. command output) stay up a little longer.
    const base = opts.duration || TOAST_DURATION[type] || 4000;
    const duration = opts.duration ? base : base + Math.min(text.length * 25, 8000);
    let remaining = duration;
    let started = Date.now();
    timer = setTimeout(close, remaining);
    toast.addEventListener('mouseenter', function () {
        clearTimeout(timer);
        remaining -= Date.now() - started;
    });
    toast.addEventListener('mouseleave', function () {
        started = Date.now();
        timer = setTimeout(close, Math.max(remaining, 1500));
    });
    return toast;
}

/* ------------------------------------------------------------------------ *
 * apiCall(url, method = 'GET', body = null, opts = {silent})
 * Resolves to the parsed JSON on real success (HTTP 2xx and status !== 'error')
 * and to null on any failure. Shows a toast either way unless opts.silent.
 * Callers can therefore safely do:  const data = await apiCall(...); if (!data) return;
 * ------------------------------------------------------------------------ */
async function apiCall(url, method, body, opts) {
    method = method || 'GET';
    body = (body === undefined) ? null : body;
    opts = opts || {};
    const fetchOpts = { method: method, headers: {} };
    if (body !== null) {
        fetchOpts.headers['Content-Type'] = 'application/json';
        fetchOpts.body = JSON.stringify(body);
    }
    let res;
    try {
        res = await fetch(url, fetchOpts);
    } catch (e) {
        if (!opts.silent) showToast('Connection error', 'error');
        return null;
    }
    let data = null;
    try {
        data = await res.json();
    } catch (e) {
        data = null;
    }
    const ok = res.ok && data !== null && data.status !== 'error';
    if (!ok) {
        if (!opts.silent && !isAuthOrCsrfFailure(res, data)) {
            const msg = (data && data.message) || (res.ok ? 'Unexpected response from server' : 'Request failed (HTTP ' + res.status + ')');
            showToast(msg, 'error');
        }
        if (opts.onError) opts.onError(res, data);
        return null;
    }
    if (!opts.silent) showToast(data.message || 'OK', 'success');
    return data;
}

/* ------------------------------------------------------------------------ *
 * withBusy(btn, asyncFn): disable a button (and show a spinner) while the
 * request runs; ignores clicks while busy to prevent double submits.
 * ------------------------------------------------------------------------ */
async function withBusy(btn, fn) {
    const buttons = (Array.isArray(btn) ? btn : [btn]).filter(Boolean);
    if (buttons.some(function (b) { return b.dataset.busy === '1'; })) return undefined;
    buttons.forEach(function (b) {
        b.dataset.busy = '1';
        b.disabled = true;
        b.classList.add('is-busy');
        b.setAttribute('aria-busy', 'true');
    });
    try {
        return await fn();
    } finally {
        buttons.forEach(function (b) {
            delete b.dataset.busy;
            b.disabled = false;
            b.classList.remove('is-busy');
            b.removeAttribute('aria-busy');
        });
    }
}

/* ------------------------------------------------------------------------ *
 * startVisiblePolling(fn, intervalMs, {immediate})
 * Runs fn every intervalMs while the tab is visible; pauses when hidden and
 * refreshes immediately when the tab becomes visible again.
 * Returns {stop()}.
 * ------------------------------------------------------------------------ */
function startVisiblePolling(fn, intervalMs, opts) {
    opts = opts || {};
    let timer = null;
    let stopped = false;
    let running = false;

    function schedule() {
        clearTimeout(timer);
        if (!stopped && !document.hidden) timer = setTimeout(tick, intervalMs);
    }
    async function tick() {
        if (stopped || running || document.hidden) return;
        running = true;
        try { await fn(); } catch (e) { /* keep polling */ }
        running = false;
        schedule();
    }
    function onVisibility() {
        if (stopped) return;
        if (document.hidden) clearTimeout(timer);
        else tick();
    }
    document.addEventListener('visibilitychange', onVisibility);
    if (opts.immediate) tick(); else schedule();
    return {
        stop: function () {
            stopped = true;
            clearTimeout(timer);
            document.removeEventListener('visibilitychange', onVisibility);
        },
    };
}

/* Bulk helper: runs apiCall silently for each item, returns {ok:[], failed:[]} */
async function runBulkRequests(items, urlFor) {
    const result = { ok: [], failed: [] };
    for (let i = 0; i < items.length; i++) {
        const data = await apiCall(urlFor(items[i]), 'POST', null, { silent: true });
        (data ? result.ok : result.failed).push(items[i]);
    }
    return result;
}

function bulkSummaryToast(result, verb, noun) {
    const total = result.ok.length + result.failed.length;
    if (!result.failed.length) {
        showToast(result.ok.length + ' ' + noun + ' ' + verb, 'success');
    } else {
        const msg = result.ok.length + ' of ' + total + ' ' + noun + ' ' + verb + '\nFailed: ' + result.failed.join(', ');
        showToast(msg, result.ok.length ? 'warning' : 'error');
    }
}

/* ------------------------------------------------------------------------ *
 * Chart helpers (shared by dashboard and uptime). Colors come from CSS
 * custom properties so the palette lives in style.css.
 * ------------------------------------------------------------------------ */
function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback || '';
}

function chartTheme() {
    return {
        grid: cssVar('--chart-grid', 'rgba(255,255,255,0.06)'),
        tick: cssVar('--chart-tick', '#8b949e'),
        text: cssVar('--text-primary', '#e6edf3'),
        textSecondary: cssVar('--text-secondary', '#b1bac4'),
        tooltipBg: cssVar('--bg-tertiary', '#1b212c'),
        tooltipBorder: cssVar('--border-strong', 'rgba(255,255,255,0.14)'),
        palette: [1, 2, 3, 4, 5, 6, 7, 8].map(function (i) { return cssVar('--chart-' + i); }).filter(Boolean),
    };
}

// '#58a6ff' -> 'rgba(88,166,255,a)'
function hexToRgba(hex, alpha) {
    const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(String(hex).trim());
    if (!m) return hex;
    return 'rgba(' + parseInt(m[1], 16) + ',' + parseInt(m[2], 16) + ',' + parseInt(m[3], 16) + ',' + alpha + ')';
}

function formatClock(ms) {
    const d = new Date(ms);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}

/* Place ticks on round local clock times (every 15m/30m/1h/2h/3h/4h/6h/12h/24h). */
function clockTicks(axis) {
    const min = axis.min, max = axis.max;
    if (!isFinite(min) || !isFinite(max) || max <= min) return;
    const minute = 60000;
    const steps = [15, 30, 60, 120, 180, 240, 360, 720, 1440].map(function (m) { return m * minute; });
    const maxTicks = axis.width && axis.width < 360 ? 4 : 7;
    const step = steps.find(function (s) { return (max - min) / s <= maxTicks; }) || steps[steps.length - 1];
    const off = new Date(min).getTimezoneOffset() * minute;
    const ticks = [];
    for (let t = Math.ceil((min - off) / step) * step + off; t <= max; t += step) ticks.push({ value: t });
    axis.ticks = ticks;
}

/* Linear time axis (ms since epoch) — no date adapter needed.
 * Callers set min/max to the data range (see fitTimeAxis). */
function timeAxis(theme) {
    return {
        type: 'linear',
        grid: { color: theme.grid },
        border: { display: false },
        afterBuildTicks: clockTicks,
        ticks: {
            color: theme.tick,
            font: { size: 11 },
            maxRotation: 0,
            callback: function (v) { return formatClock(v); },
        },
    };
}

/* Fit the x axis to the first/last x of all datasets. */
function fitTimeAxis(chart) {
    let min = Infinity, max = -Infinity;
    chart.data.datasets.forEach(function (ds) {
        const d = ds.data;
        if (d && d.length) {
            min = Math.min(min, d[0].x);
            max = Math.max(max, d[d.length - 1].x);
        }
    });
    if (isFinite(min) && isFinite(max) && max > min) {
        chart.options.scales.x.min = min;
        chart.options.scales.x.max = max;
    }
}

function baseTooltip(theme) {
    return {
        backgroundColor: theme.tooltipBg,
        borderColor: theme.tooltipBorder,
        borderWidth: 1,
        titleColor: theme.text,
        bodyColor: theme.textSecondary,
        padding: 10,
        titleFont: { size: 12 },
        bodyFont: { size: 12 },
        callbacks: {
            title: function (items) { return items.length ? formatClock(items[0].parsed.x) : ''; },
        },
    };
}

/* ------------------------------------------------------------------------ *
 * PM2 actions / logs modal
 * ------------------------------------------------------------------------ */
async function pm2Action(action, name, btn) {
    const data = await withBusy(btn, function () {
        return apiCall('/pm2/' + encodeURIComponent(action) + '/' + encodeURIComponent(name), 'POST');
    });
    if (!data) return;
    const row = btn ? btn.closest('tr') : null;
    if (row) {
        const statusCell = row.querySelector('td[data-label="Status"]') || row.querySelector('td:nth-child(3)');
        if (statusCell) {
            if (action === 'stop') {
                statusCell.innerHTML = '<span class="badge badge-yellow"><span class="badge-dot yellow"></span>stopped</span>';
            } else {
                statusCell.innerHTML = '<span class="badge badge-green"><span class="badge-dot green"></span>online</span>';
            }
        }
    } else {
        setTimeout(function () { location.reload(); }, 1500);
    }
}

let _lastFocusBeforeModal = null;

async function showLogs(name) {
    const modal = document.getElementById('logModal');
    _lastFocusBeforeModal = document.activeElement;
    modal.style.display = 'flex';
    document.getElementById('logModalTitle').textContent = 'Logs: ' + name;
    const content = document.getElementById('logModalContent');
    content.textContent = 'Loading...';
    const closeBtn = modal.querySelector('.vps-modal-close');
    if (closeBtn) closeBtn.focus();
    try {
        const res = await fetch('/pm2/logs/' + encodeURIComponent(name));
        const data = await res.json();
        content.textContent = res.ok ? (data.logs || 'No logs') : (data.message || 'Failed to load logs');
    } catch (e) {
        content.textContent = 'Failed to load logs';
    }
}

function closeLogModal() {
    const modal = document.getElementById('logModal');
    if (!modal) return;
    const wasOpen = modal.style.display === 'flex';
    modal.style.display = 'none';
    if (wasOpen && _lastFocusBeforeModal && _lastFocusBeforeModal.focus) {
        try { _lastFocusBeforeModal.focus(); } catch (e) { /* element gone */ }
    }
    _lastFocusBeforeModal = null;
}

/* ------------------------------------------------------------------------ *
 * Confirm dialog
 * showConfirm(title, message, callback, opts = {destructive, confirmLabel})
 * Neutral styling unless destructive (auto-detected from the title when not
 * given). Focus goes to the primary button, Enter confirms, Esc cancels.
 * ------------------------------------------------------------------------ */
let confirmCallback = null;
let _confirmReturnFocus = null;
const DESTRUCTIVE_RE = /\b(reboot|delete|kill|stop|clear|remove|ban|disable|drop|wipe|uninstall|shutdown|unban)\b/i;

function showConfirm(title, message, callback, opts) {
    opts = opts || {};
    const overlay = document.getElementById('confirmOverlay');
    const box = overlay.querySelector('.confirm-box');
    const btn = document.getElementById('confirmBtn');
    const destructive = (typeof opts.destructive === 'boolean') ? opts.destructive : DESTRUCTIVE_RE.test(String(title || ''));

    document.getElementById('confirmTitle').textContent = title;
    document.getElementById('confirmMessage').textContent = message;
    box.classList.toggle('is-destructive', destructive);
    btn.className = 'btn ' + (destructive ? 'btn-danger' : 'btn-primary');
    btn.textContent = opts.confirmLabel || 'Confirm';

    confirmCallback = callback;
    _confirmReturnFocus = document.activeElement;
    overlay.classList.add('active');
    setTimeout(function () { btn.focus(); }, 0);
}

function closeConfirm() {
    const overlay = document.getElementById('confirmOverlay');
    const wasOpen = overlay.classList.contains('active');
    overlay.classList.remove('active');
    confirmCallback = null;
    if (wasOpen && _confirmReturnFocus && _confirmReturnFocus.focus && document.contains(_confirmReturnFocus)) {
        try { _confirmReturnFocus.focus(); } catch (e) { /* ignore */ }
    }
    _confirmReturnFocus = null;
}

function executeConfirm() {
    const cb = confirmCallback;
    closeConfirm();
    if (cb) cb();
}

function isConfirmOpen() {
    const o = document.getElementById('confirmOverlay');
    return !!(o && o.classList.contains('active'));
}

/* Reboot: an explicit, clearly-labelled action (top-bar menu, command palette,
 * dashboard button) that always goes through the confirm dialog. */
function confirmReboot() {
    closeServerMenu();
    showConfirm('Reboot server',
        'Are you sure you want to reboot the VPS? All services will be temporarily unavailable.',
        function () { apiCall('/reboot', 'POST'); },
        { destructive: true, confirmLabel: 'Reboot' });
}

// Kept for backwards compatibility with older markup.
function rebootFromTopbar() { confirmReboot(); }

/* ------------------------------------------------------------------------ *
 * Top-bar: copy IP, server menu, mobile sidebar
 * ------------------------------------------------------------------------ */
function copyIp() {
    const ip = document.getElementById('serverIp').textContent;
    if (!navigator.clipboard) { showToast('Clipboard not available', 'error'); return; }
    navigator.clipboard.writeText(ip).then(function () {
        showToast('IP copied', 'success');
    }, function () {
        showToast('Could not copy IP', 'error');
    });
}

function toggleServerMenu(e) {
    if (e) e.stopPropagation();
    const menu = document.getElementById('serverMenu');
    const btn = document.getElementById('serverMenuBtn');
    if (!menu || !btn) return;
    const open = menu.hidden;
    closeNotifDropdown();
    menu.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    if (open) {
        const first = menu.querySelector('.menu-item');
        if (first) first.focus();
    }
}

function closeServerMenu() {
    const menu = document.getElementById('serverMenu');
    const btn = document.getElementById('serverMenuBtn');
    if (menu && !menu.hidden) {
        menu.hidden = true;
        if (btn) btn.setAttribute('aria-expanded', 'false');
    }
}

function toggleSidebar(e) {
    if (e) e.stopPropagation();
    const sidebar = document.getElementById('sidebar');
    const open = !sidebar.classList.contains('open');
    sidebar.classList.toggle('open', open);
    document.querySelectorAll('[aria-controls="sidebar"]').forEach(function (b) {
        b.setAttribute('aria-expanded', String(open));
    });
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar || !sidebar.classList.contains('open')) return;
    sidebar.classList.remove('open');
    document.querySelectorAll('[aria-controls="sidebar"]').forEach(function (b) {
        b.setAttribute('aria-expanded', 'false');
    });
}

/* ------------------------------------------------------------------------ *
 * Notifications (bell)
 * The badge uses the cheap /api/notifications/unread-count; the full history
 * is only downloaded when the dropdown opens.
 * ------------------------------------------------------------------------ */
const NOTIF_EMPTY = '<div class="empty-state" style="padding:20px;font-size:13px;">No notifications yet</div>';
const NOTIF_SKELETON = '<div class="skeleton-stack" style="padding:14px 16px" aria-busy="true" aria-label="Loading"><div class="skeleton skeleton-line"></div><div class="skeleton skeleton-line"></div><div class="skeleton skeleton-line"></div></div>';

function toggleNotifDropdown(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('notifDropdown');
    const bell = document.getElementById('notifBell');
    const isOpen = dropdown.style.display === 'flex';
    closeServerMenu();
    dropdown.style.display = isOpen ? 'none' : 'flex';
    if (bell) bell.setAttribute('aria-expanded', String(!isOpen));
    if (!isOpen) loadNotifHistory();
}

function closeNotifDropdown() {
    const dropdown = document.getElementById('notifDropdown');
    if (!dropdown) return;
    dropdown.style.display = 'none';
    const bell = document.getElementById('notifBell');
    if (bell) bell.setAttribute('aria-expanded', 'false');
}

function escNotif(str) {
    return escHtml(str || '');
}

const NOTIF_CATEGORY_COLORS = {
    critical: 'var(--red)', error: 'var(--red)',
    warning: 'var(--yellow)', warnings: 'var(--yellow)',
    security: 'var(--purple)', ddos: 'var(--red)',
    backup: 'var(--cyan)', updates: 'var(--accent)',
    test: 'var(--green)',
};

async function loadNotifHistory() {
    const body = document.getElementById('notifDropdownBody');
    body.innerHTML = NOTIF_SKELETON;
    try {
        const res = await fetch('/api/notifications/history');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const items = await res.json();
        if (!Array.isArray(items) || !items.length) {
            body.innerHTML = NOTIF_EMPTY;
            return;
        }
        body.innerHTML = items.slice(0, 50).map(function (item, idx) {
            const d = new Date(item.timestamp);
            const time = d.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit' }) + ' ' + d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
            const cat = escNotif(item.category);
            const color = NOTIF_CATEGORY_COLORS[item.category] || 'var(--text-muted)';
            const unread = item.read ? '' : ' notif-item-unread';
            const count = item.count > 1 ? ' <span style="opacity:0.5">(' + escHtml(item.count) + 'x)</span>' : '';
            const idAttr = (item.id != null) ? ' data-notif-id="' + escHtml(item.id) + '"' : '';
            return '<div class="notif-item' + unread + '" data-notif-idx="' + idx + '"' + idAttr + '>' +
                '<div class="notif-item-bar" style="background:' + color + '"></div>' +
                '<div class="notif-item-content"><div class="notif-item-body">' + escNotif(item.body) + count + '</div>' +
                '<div class="notif-item-time">' + escHtml(time) + ' &middot; ' + cat + '</div></div>' +
                '<button type="button" class="notif-dismiss-btn" onclick="dismissNotification(event, this)" title="Dismiss" aria-label="Dismiss notification">&times;</button></div>';
        }).join('');
    } catch (e) {
        body.innerHTML = '<div class="empty-state" style="padding:20px;font-size:13px;">Could not load notifications</div>';
    }
}

async function dismissNotification(e, btn) {
    if (e) e.stopPropagation();
    const item = btn && btn.closest ? btn.closest('.notif-item') : null;
    if (!item) return;
    // Prefer the stable id; the positional index is only a legacy fallback.
    const payload = item.dataset.notifId
        ? { id: item.dataset.notifId }
        : { index: parseInt(item.dataset.notifIdx, 10) };
    try {
        const res = await fetch('/api/notifications/dismiss', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            let msg = 'Could not dismiss notification';
            try { msg = (await res.json()).message || msg; } catch (err) { /* ignore */ }
            showToast(msg, 'error');
            loadNotifHistory();
            return;
        }
        item.style.transition = 'opacity 0.2s, max-height 0.3s';
        item.style.opacity = '0';
        item.style.maxHeight = item.offsetHeight + 'px';
        setTimeout(function () { item.style.maxHeight = '0'; item.style.padding = '0'; }, 150);
        setTimeout(function () {
            item.remove();
            const body = document.getElementById('notifDropdownBody');
            if (body && !body.querySelector('.notif-item')) body.innerHTML = NOTIF_EMPTY;
            updateNotifBadge();
        }, 350);
    } catch (err) {
        showToast('Connection error', 'error');
    }
}

function setNotifBadge(unread) {
    const badge = document.getElementById('notifBadge');
    const bell = document.getElementById('notifBell');
    if (!badge) return;
    if (unread > 0) {
        badge.textContent = unread > 99 ? '99+' : String(unread);
        badge.style.display = 'flex';
    } else {
        badge.textContent = '0';
        badge.style.display = 'none';
    }
    if (bell) bell.setAttribute('aria-label', unread > 0 ? 'Notifications (' + unread + ' unread)' : 'Notifications');
}

async function markAllRead(e) {
    if (e) e.stopPropagation();
    try {
        const res = await fetch('/api/notifications/read', { method: 'POST' });
        if (!res.ok) { showToast('Could not mark notifications as read', 'error'); return; }
        setNotifBadge(0);
        document.querySelectorAll('.notif-item-unread').forEach(function (el) { el.classList.remove('notif-item-unread'); });
    } catch (err) {
        showToast('Connection error', 'error');
    }
}

async function clearAllNotifications(e) {
    if (e) e.stopPropagation();
    try {
        const res = await fetch('/api/notifications/clear', { method: 'POST' });
        if (!res.ok) { showToast('Could not clear notifications', 'error'); return; }
        setNotifBadge(0);
        document.getElementById('notifDropdownBody').innerHTML = NOTIF_EMPTY;
    } catch (err) {
        showToast('Connection error', 'error');
    }
}

async function updateNotifBadge() {
    try {
        const res = await fetch('/api/notifications/unread-count');
        if (res.ok) {
            const data = await res.json();
            setNotifBadge(parseInt(data.unread, 10) || 0);
            return;
        }
        if (res.status === 404) {
            // Older backend without the count endpoint.
            const hist = await fetch('/api/notifications/history');
            if (!hist.ok) return;
            const items = await hist.json();
            setNotifBadge(items.filter(function (i) { return !i.read; }).length);
        }
    } catch (e) { /* offline: leave badge as is */ }
}

/* ------------------------------------------------------------------------ *
 * Sidebar groups (collapsible, state remembered per browser)
 * ------------------------------------------------------------------------ */
function toggleSidebarGroup(header) {
    const group = header.closest('.sidebar-group');
    const collapsed = group.classList.toggle('collapsed');
    header.setAttribute('aria-expanded', String(!collapsed));
    saveSidebarState();
}

function saveSidebarState() {
    const state = {};
    document.querySelectorAll('.sidebar-group').forEach(function (g) {
        state[g.dataset.group] = g.classList.contains('collapsed');
    });
    try { localStorage.setItem('sidebarGroups', JSON.stringify(state)); } catch (e) { /* storage blocked */ }
}

function initSidebarGroups() {
    let state = {};
    try { state = JSON.parse(localStorage.getItem('sidebarGroups') || '{}') || {}; } catch (e) { state = {}; }
    document.querySelectorAll('.sidebar-group').forEach(function (g) {
        const hasActive = g.querySelector('.sidebar-group-items a.active');
        if (hasActive) g.classList.remove('collapsed');
        else if (state[g.dataset.group]) g.classList.add('collapsed');
        const header = g.querySelector('.sidebar-group-header');
        if (header) header.setAttribute('aria-expanded', String(!g.classList.contains('collapsed')));
    });
}

/* ------------------------------------------------------------------------ *
 * Command palette
 * ------------------------------------------------------------------------ */
const WS_NAME = VPS.webServer === 'caddy' ? 'Caddy' : 'Nginx';
const WS_UNIT = VPS.webServer === 'caddy' ? 'caddy' : 'nginx';

async function cmdValidateConfig() {
    try {
        const res = await fetch('/api/webserver/validate', { method: 'POST' });
        const data = await res.json().catch(function () { return null; });
        if (!res.ok || !data) {
            if (!isAuthOrCsrfFailure(res, data)) showToast((data && data.message) || 'Validation request failed (HTTP ' + res.status + ')', 'error');
            return;
        }
        if (data.valid) showToast(WS_NAME + ' config OK', 'success');
        else showToast(WS_NAME + ' config invalid' + (data.output ? '\n\n' + String(data.output).substring(0, 600) : ''), 'error');
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function cmdCheckUpdates() {
    showToast('Checking for updates...', 'info');
    try {
        const res = await fetch('/api/update/check');
        const data = await res.json().catch(function () { return null; });
        if (!res.ok || !data || data.status === 'error') {
            if (!isAuthOrCsrfFailure(res, data)) showToast((data && data.message) || 'Update check failed', 'error');
            return;
        }
        if (data.available) {
            showToast('Update available: ' + data.latest, 'success');
            window.location.href = '/updates';
        } else {
            showToast('Already up to date', 'success');
        }
    } catch (e) {
        showToast('Connection error', 'error');
    }
}

async function cmdTestPush() {
    let endpoint = null;
    try {
        if ('serviceWorker' in navigator && 'PushManager' in window) {
            const reg = await Promise.race([
                navigator.serviceWorker.ready,
                new Promise(function (_, reject) { setTimeout(function () { reject(new Error('timeout')); }, 3000); }),
            ]);
            const sub = await reg.pushManager.getSubscription();
            if (sub) endpoint = sub.endpoint;
        }
    } catch (e) { /* no service worker / push */ }
    if (!endpoint) {
        showToast('Push is not enabled on this device. Enable it on the Notifications page.', 'warning', {
            action: { label: 'Open', onClick: function () { location.href = '/notifications'; } },
        });
        return;
    }
    await apiCall('/api/push/test', 'POST', { endpoint: endpoint });
}

const cmdPages = (function buildCmdPages() {
    const list = [
        { label: 'Dashboard', url: '/', keywords: 'home overview stats' },
        { label: 'Websites', url: '/websites', keywords: 'sites domains nginx caddy' },
        { label: 'Uptime', url: '/uptime', keywords: 'monitor status check' },
    ];
    if (VPS.hasPm2) list.push({ label: 'PM2 Processes', url: '/pm2', keywords: 'node process manager' });
    list.push(
        { label: WS_NAME + ' Logs', url: '/web-logs', keywords: 'error access log nginx caddy' },
        { label: WS_NAME + ' Config', url: '/web-config', keywords: 'configuration edit site caddyfile' },
        { label: 'SSL Certificates', url: '/ssl', keywords: 'https lets encrypt renew caddy auto' },
        { label: 'DNS Records', url: '/dns', keywords: 'domain lookup' },
        { label: 'Services', url: '/services', keywords: 'systemd systemctl restart' },
        { label: 'Processes', url: '/processes', keywords: 'top kill pid cpu memory' },
        { label: 'Network', url: '/network', keywords: 'interfaces ports connections' }
    );
    if (VPS.hasMysql) list.push({ label: 'Databases', url: '/databases', keywords: 'mariadb mysql phpmyadmin' });
    if (VPS.hasPhp) list.push({ label: 'PHP', url: '/php', keywords: 'fpm version restart' });
    list.push(
        { label: 'Cronjobs', url: '/cronjobs', keywords: 'cron schedule timer' },
        { label: 'Disk Usage', url: '/disk', keywords: 'space storage' },
        { label: 'Files', url: '/files', keywords: 'browser upload download' },
        { label: 'Security Audit', url: '/security', keywords: 'hardening score checks' },
        { label: 'SSH Logs', url: '/ssh-logs', keywords: 'ssh auth brute force login failed ban' },
        { label: 'Firewall', url: '/firewall', keywords: 'ufw fail2ban security ban' },
        { label: 'Backup', url: '/backup', keywords: 'restore nas' },
        { label: 'Updates', url: '/updates', keywords: 'packages security upgrade' },
        { label: 'Terminal', url: '/terminal', keywords: 'ssh command shell' },
        { label: 'Notifications', url: '/notifications', keywords: 'push alerts subscribe' },
        { label: 'Audit Log', url: '/audit', keywords: 'history actions log' },
        { label: 'Settings', url: '/settings', keywords: 'config password 2fa thresholds' }
    );

    // Actions
    list.push(
        {
            label: VPS.webServer === 'caddy' ? 'Reload Caddy' : 'Renew All SSL', type: 'action',
            keywords: 'certificate https lets encrypt renew caddy',
            action: function () {
                showConfirm(VPS.webServer === 'caddy' ? 'Reload Caddy' : 'SSL Renewal',
                    VPS.webServer === 'caddy' ? 'Reload Caddy to trigger certificate check?' : 'Force renew all certificates?',
                    function () { apiCall('/ssl/renew', 'POST', {}); });
            },
        },
        { label: 'Validate ' + WS_NAME + ' Config', type: 'action', keywords: 'test nginx caddy configuration check validate', action: cmdValidateConfig },
        { label: 'Check for Updates', type: 'action', keywords: 'upgrade version new release', action: cmdCheckUpdates },
        {
            label: 'Restart ' + WS_NAME, type: 'action', keywords: 'reload web server nginx caddy',
            action: function () {
                showConfirm('Restart ' + WS_NAME, 'Restart the ' + WS_NAME + ' web server?',
                    function () { apiCall('/services/restart/' + WS_UNIT, 'POST'); });
            },
        }
    );
    if (VPS.hasPhp) {
        // The FPM unit name depends on the installed version(s); the PHP page lists them.
        list.push({ label: 'Manage PHP-FPM (restart per version)', type: 'action', keywords: 'php fpm reload restart', action: function () { location.href = '/php'; } });
    }
    if (VPS.hasMysql) {
        list.push({
            label: 'Restart MariaDB', type: 'action', keywords: 'mysql database reload',
            action: function () {
                showConfirm('Restart MariaDB', 'Restart the MariaDB database server?',
                    function () { apiCall('/services/restart/mariadb', 'POST'); });
            },
        });
    }
    list.push(
        {
            label: 'Clear Audit Log', type: 'action', danger: true, keywords: 'delete history wipe',
            action: function () {
                showConfirm('Clear Audit Log', 'Delete all audit log entries?', function () { apiCall('/api/audit/clear', 'POST'); });
            },
        },
        { label: 'Test Push Notification', type: 'action', keywords: 'notify alert test', action: cmdTestPush },
        { label: 'Detect Services', type: 'action', keywords: 'discover scan systemd', action: function () { location.href = '/settings'; } },
        { label: 'Reboot Server…', type: 'action', danger: true, keywords: 'restart shutdown power reboot', action: confirmReboot },
        { label: 'Logout', type: 'action', keywords: 'sign out exit session', action: doLogout }
    );
    return list;
})();

let cmdSelectedIdx = 0;
let cmdFiltered = [];

function openCmdPalette() {
    closeServerMenu();
    closeNotifDropdown();
    const overlay = document.getElementById('cmdPalette');
    overlay.classList.add('active');
    const input = document.getElementById('cmdInput');
    input.value = '';
    input.focus();
    cmdSelectedIdx = 0;
    filterCmd('');
}

function closeCmdPalette() {
    document.getElementById('cmdPalette').classList.remove('active');
}

function filterCmd(query) {
    const q = query.toLowerCase().trim();
    cmdFiltered = q ? cmdPages.filter(function (p) {
        return p.label.toLowerCase().indexOf(q) !== -1 || p.keywords.toLowerCase().indexOf(q) !== -1;
    }) : cmdPages;
    cmdSelectedIdx = 0;
    renderCmdResults();
}

function renderCmdResults() {
    const container = document.getElementById('cmdResults');
    if (!cmdFiltered.length) {
        container.innerHTML = '<div class="empty-state" style="padding:20px">No matches</div>';
        return;
    }
    container.innerHTML = cmdFiltered.map(function (p, i) {
        const cls = 'cmd-result-item' + (i === cmdSelectedIdx ? ' selected' : '') + (p.danger ? ' is-danger' : '');
        const type = p.type === 'action'
            ? '<span class="cmd-type is-action">Action</span>'
            : '<span class="cmd-type">Page</span>';
        return '<div class="' + cls + '" role="option" id="cmd-opt-' + i + '" aria-selected="' + (i === cmdSelectedIdx) + '" data-idx="' + i + '">' +
            '<span class="cmd-label">' + escHtml(p.label) + '</span>' + type + '</div>';
    }).join('');
    const input = document.getElementById('cmdInput');
    input.setAttribute('aria-activedescendant', 'cmd-opt-' + cmdSelectedIdx);
    const sel = container.querySelector('.selected');
    if (sel && sel.scrollIntoView) sel.scrollIntoView({ block: 'nearest' });
}

function navigateCmd(idx) {
    const item = cmdFiltered[idx];
    if (!item) return;
    closeCmdPalette();
    if (item.action) item.action();
    else if (item.url) window.location.href = item.url;
}

/* ------------------------------------------------------------------------ *
 * Navigation progress bar (internal link clicks + form submits)
 * ------------------------------------------------------------------------ */
function startNavProgress() {
    const bar = document.getElementById('navProgress');
    if (!bar) return;
    bar.classList.remove('done');
    void bar.offsetWidth; // restart the transition
    bar.classList.add('active');
}

function stopNavProgress() {
    const bar = document.getElementById('navProgress');
    if (!bar || !bar.classList.contains('active')) return;
    bar.classList.remove('active');
    bar.classList.add('done');
    setTimeout(function () { bar.classList.remove('done'); }, 500);
}

function isInternalNavigation(a, e) {
    if (!a || e.defaultPrevented || e.button !== 0) return false;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return false;
    if (a.target && a.target !== '_self') return false;
    if (a.hasAttribute('download')) return false;
    const href = a.getAttribute('href');
    if (!href || href.charAt(0) === '#' || /^(javascript|mailto|tel):/i.test(href)) return false;
    let url;
    try { url = new URL(a.href, location.href); } catch (err) { return false; }
    if (url.origin !== location.origin) return false;
    // Same page, only the hash differs
    if (url.pathname === location.pathname && url.search === location.search && url.hash) return false;
    // Downloads served by the app
    if (/\/(download|export)\b/i.test(url.pathname)) return false;
    return true;
}

/* ------------------------------------------------------------------------ *
 * Wiring (the DOM above this script is already parsed)
 * ------------------------------------------------------------------------ */
(function wireUp() {
    initSidebarGroups();

    const logModal = document.getElementById('logModal');
    if (logModal) {
        logModal.addEventListener('click', function (e) { if (e.target === this) closeLogModal(); });
    }
    const confirmOverlay = document.getElementById('confirmOverlay');
    if (confirmOverlay) {
        confirmOverlay.addEventListener('click', function (e) { if (e.target === this) closeConfirm(); });
    }

    const cmdInput = document.getElementById('cmdInput');
    if (cmdInput) {
        cmdInput.addEventListener('input', function () { filterCmd(this.value); });
        cmdInput.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                cmdSelectedIdx = Math.min(cmdSelectedIdx + 1, cmdFiltered.length - 1);
                renderCmdResults();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                cmdSelectedIdx = Math.max(cmdSelectedIdx - 1, 0);
                renderCmdResults();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                navigateCmd(cmdSelectedIdx);
            }
        });
    }
    const cmdResults = document.getElementById('cmdResults');
    if (cmdResults) {
        cmdResults.addEventListener('click', function (e) {
            const opt = e.target.closest('.cmd-result-item');
            if (opt) navigateCmd(parseInt(opt.dataset.idx, 10));
        });
        cmdResults.addEventListener('mousemove', function (e) {
            const opt = e.target.closest('.cmd-result-item');
            if (!opt) return;
            const idx = parseInt(opt.dataset.idx, 10);
            if (idx !== cmdSelectedIdx) {
                cmdSelectedIdx = idx;
                renderCmdResults();
            }
        });
    }
    const cmdPalette = document.getElementById('cmdPalette');
    if (cmdPalette) {
        cmdPalette.addEventListener('click', function (e) { if (e.target === this) closeCmdPalette(); });
    }

    // Close popovers when clicking elsewhere
    document.addEventListener('click', function (e) {
        if (!e.target.closest('.notif-wrap')) closeNotifDropdown();
        if (!e.target.closest('.menu-wrap')) closeServerMenu();
    });

    // Keyboard handling
    document.addEventListener('keydown', function (e) {
        if (isConfirmOpen()) {
            if (e.key === 'Escape') {
                e.preventDefault();
                closeConfirm();
                return;
            }
            if (e.key === 'Enter') {
                // Enter on the Cancel button cancels (native click); anywhere else confirms.
                const t = e.target;
                if (t && t.closest && t.closest('#confirmOverlay') && t.tagName === 'BUTTON' && t.id !== 'confirmBtn') return;
                e.preventDefault();
                executeConfirm();
                return;
            }
            if (e.key === 'Tab') {
                // Keep focus inside the dialog
                const focusables = Array.prototype.slice.call(document.querySelectorAll('#confirmOverlay button'));
                if (focusables.length) {
                    const i = focusables.indexOf(document.activeElement);
                    e.preventDefault();
                    const next = e.shiftKey ? (i <= 0 ? focusables.length - 1 : i - 1) : (i + 1) % focusables.length;
                    focusables[next].focus();
                }
                return;
            }
        }
        if (e.key === 'Escape') {
            if (document.getElementById('cmdPalette').classList.contains('active')) {
                closeCmdPalette();
                return;
            }
            const menu = document.getElementById('serverMenu');
            if (menu && !menu.hidden) {
                closeServerMenu();
                const btn = document.getElementById('serverMenuBtn');
                if (btn) btn.focus();
                return;
            }
            closeLogModal();
            closeNotifDropdown();
            closeSidebar();
        }
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
            e.preventDefault();
            openCmdPalette();
        }
    });

    // Arrow-key navigation inside the server menu
    const serverMenu = document.getElementById('serverMenu');
    if (serverMenu) {
        serverMenu.addEventListener('keydown', function (e) {
            if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
            e.preventDefault();
            const items = Array.prototype.slice.call(serverMenu.querySelectorAll('.menu-item'));
            const i = items.indexOf(document.activeElement);
            const next = e.key === 'ArrowDown' ? (i + 1) % items.length : (i <= 0 ? items.length - 1 : i - 1);
            items[next].focus();
        });
    }

    // Navigation progress
    document.addEventListener('click', function (e) {
        const a = e.target.closest ? e.target.closest('a[href]') : null;
        if (a && isInternalNavigation(a, e)) {
            closeSidebar();
            startNavProgress();
        }
    });
    document.addEventListener('submit', function (e) {
        const form = e.target;
        if (e.defaultPrevented || !form || (form.target && form.target !== '_self')) return;
        startNavProgress();
    });
    window.addEventListener('pageshow', stopNavProgress);
    window.addEventListener('pagehide', function () { setTimeout(stopNavProgress, 0); });

    // Badge: cheap unread count on load, refreshed when the tab regains focus.
    updateNotifBadge();
    let lastBadgeRefresh = Date.now();
    document.addEventListener('visibilitychange', function () {
        if (!document.hidden && Date.now() - lastBadgeRefresh > 60000) {
            lastBadgeRefresh = Date.now();
            updateNotifBadge();
        }
    });
})();
