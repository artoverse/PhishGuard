// ================================================
// PhishGuard – Dashboard Script
// Per-session Pause / Resume / Reset controls
// Separate phishing domain list per session
// ================================================

let currentSessionId = null;
let riskChartInstance = null;
let socket = null;
let allSessions = [];
let sessionPollTimer = null;   // auto-refresh sidebar while any scan is running

// ── XSS helper ──────────────────────────────────────────────────────────────
function esc(s) {
    if (s == null) return '—';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Toast ────────────────────────────────────────────────────────────────────
function showToast(msg, type = 'error') {
    const toast = document.getElementById('toast');
    const icon  = document.getElementById('toast-icon');
    const text  = document.getElementById('toast-text');
    if (!toast) return;
    if (icon) icon.className =
        type === 'success' ? 'fas fa-check-circle text-emerald-400' :
        type === 'warn'    ? 'fas fa-pause-circle text-amber-400'    :
                             'fas fa-exclamation-triangle text-red-400';
    if (text) text.innerHTML = msg;
    toast.style.display = 'flex';
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { toast.style.display = 'none'; }, 5000);
}

// ── SocketIO ─────────────────────────────────────────────────────────────────
function initSocket() {
    try {
        socket = io();
        socket.on('connect', () => console.log('%c🛡️ PhishGuard SocketIO connected', 'color:#10b981;font-weight:bold'));
        socket.on('new_alert', (data) => {
            showToast(`🚨 ${data.domain} → ${data.status} (${data.score})`, 'error');
            if (data.session_id === currentSessionId) loadSessionDomains(currentSessionId);
            fetchSessions();
        });
        
        let lastChartUpdate = 0;
        socket.on('scan_update', (data) => {
            const onGlobalView = !currentSessionId;
            const onMatchingSessionView = currentSessionId === data.session_id;

            // 1. Instantly bump Risk Chart and Cards if data belongs to current view
            if (onGlobalView || onMatchingSessionView) {
                if (riskChartInstance) {
                    const ds = riskChartInstance.data.datasets[0].data;
                    if (data.status === 'Malicious') ds[2]++;
                    else if (data.status === 'Suspicious') ds[1]++;
                    else ds[0]++;
                    riskChartInstance.update();
                    renderRiskCards({ safe: ds[0], suspicious: ds[1], malicious: ds[2] });
                }
            }

            // 2. Inject table rows seamlessly to avoid repaints
            if (onMatchingSessionView) {
                // Update Progress bar text
                const sb = document.getElementById('scan-status-bar');
                if (sb && data.total > 0) {
                    const statusText = sb.querySelector('.text-xs.text-gray-400');
                    if (statusText) statusText.innerText = `${data.found} of ${data.total} domains resolved`;
                }
                
                const tbody = document.getElementById('domains-body');
                if (tbody) {
                    if (tbody.innerText.includes('No phishing domains')) tbody.innerHTML = '';
                    
                    const tr = document.createElement('tr');
                    tr.className = "group border-b border-gray-800/50 bg-blue-500/10 transition-colors cursor-pointer";
                    tr.style.animation = "slide-in-right 0.3s ease-out forwards";
                    tr.onclick = () => openDomainModal(data.domain, data.session_id);
                    
                    const emj = data.status === 'Malicious' ? '☠️' : data.status === 'Suspicious' ? '⚠️' : '🟢';
                    const color = data.status === 'Malicious' ? 'text-red-400' : data.status === 'Suspicious' ? 'text-amber-400' : 'text-emerald-400';
                    
                    tr.innerHTML = `
                        <td class="px-8 py-5 font-medium font-mono text-sm">
                            <span class="inline-block w-2 h-2 rounded-full bg-blue-400 animate-ping mr-2"></span>${data.domain}
                        </td>
                        <td class="px-8 py-5"><span class="inline-flex items-center gap-2 font-semibold text-sm ${color}">${emj} ${data.status}</span></td>
                        <td class="px-8 py-5 font-mono text-sm">${data.score}</td>
                        <td class="px-8 py-5 text-center text-sm">—</td>
                        <td class="px-8 py-5 text-gray-500 text-sm truncate italic">Processing...</td>
                        <td class="px-8 py-5 font-mono text-center text-sm text-gray-500">—</td>
                        <td class="px-8 py-5 text-right"><span class="text-xs text-blue-400 opacity-0 group-hover:opacity-100 transition inline-flex justify-end items-center gap-1"><i class="fas fa-search-plus"></i> Details</span></td>
                    `;
                    tbody.prepend(tr);
                    
                    setTimeout(() => {
                        tr.classList.remove('bg-blue-500/10');
                        tr.classList.add('hover:bg-gray-800/50');
                        const dot = tr.querySelector('.animate-ping');
                        if (dot) dot.remove();
                    }, 1500);
                }
            } 
            
            // 3. Inject table rows seamlessly into "Recent Activity" to avoid repaints
            if (onGlobalView || onMatchingSessionView) {
                const rt = document.querySelector('#recent-table tbody');
                if (rt) {
                    if (rt.innerText.includes('No domains yet')) rt.innerHTML = '';
                    
                    const tr = document.createElement('tr');
                    tr.className = "border-b border-gray-800 bg-blue-500/10 transition-colors";
                    tr.style.animation = "slide-in-right 0.3s ease-out forwards";
                    
                    const color = data.status === 'Malicious' ? 'bg-red-500/20 text-red-400' : data.status === 'Suspicious' ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400';
                    tr.innerHTML = `
                        <td class="py-4 font-mono text-xs truncate pr-2"><span class="inline-block w-2 h-2 rounded-full bg-blue-400 animate-ping mr-2"></span>${data.domain}</td>
                        <td><span class="px-3 py-1 text-[10px] uppercase font-bold tracking-wider rounded-3xl ${color}">${data.status}</span></td>
                        <td class="font-medium text-center text-xs opacity-90">${data.score}</td>
                        <td class="text-gray-500 text-[11px] text-right truncate pl-2">Just now</td>
                    `;
                    rt.prepend(tr);
                    
                    setTimeout(() => {
                        tr.classList.remove('bg-blue-500/10');
                        tr.classList.add('hover:bg-gray-800/30');
                        const dot = tr.querySelector('.animate-ping');
                        if (dot) dot.remove();
                    }, 1500);
                }
            }
            
            // Background sidebar sync every 2 seconds
            const now = Date.now();
            if (now - lastChartUpdate > 2000) {
                fetchSessions();
                lastChartUpdate = now;
            }
        });

        socket.on('scan_log', (data) => {
            // Only render log if it belongs to the currently viewed session
            if (currentSessionId !== data.session_id) return;

            const container = document.getElementById('session-logs-container');
            if (!container) return;

            // Remove placeholder if it exists
            const placeholder = container.querySelector('.italic');
            if (placeholder) placeholder.remove();

            // Setup color maps
            const colorMap = {
                'info': 'text-blue-400',
                'warning': 'text-amber-400',
                'error': 'text-red-400',
                'success': 'text-emerald-400'
            };
            const col = colorMap[data.level] || 'text-gray-400';

            // Format date HH:MM:SS
            const d = new Date(data.timestamp);
            const timeStr = d.toLocaleTimeString('en-US', { hour12: false });

            const logRow = document.createElement('div');
            logRow.className = "flex gap-3 leading-snug hover:bg-gray-800/30 px-2 py-1 -mx-2 rounded transition-colors";
            logRow.innerHTML = `
                <span class="text-gray-600 shrink-0 select-none">[${timeStr}]</span>
                <span class="${col}">${esc(data.message)}</span>
            `;
            
            // Auto-scroll to bottom
            container.appendChild(logRow);
            container.scrollTop = container.scrollHeight;
        });

        socket.on('disconnect', () => console.warn('⚠️ SocketIO disconnected'));
    } catch (e) { console.warn('SocketIO unavailable:', e.message); }
}

// ── SESSIONS SIDEBAR ─────────────────────────────────────────────────────────
async function fetchSessions() {
    try {
        const res = await fetch('/api/sessions');
        allSessions = await res.json();
        renderSessions();

        // Keep auto-refreshing sidebar while any scan is running or paused
        const hasActive = allSessions.some(s => s.status === 'running' || s.status === 'paused');
        if (hasActive && !sessionPollTimer) {
            sessionPollTimer = setInterval(() => {
                fetchSessions();
                // Do a final refresh ONLY if the session just finished, otherwise let WebSockets handle the live UI!
                if (currentSessionId) {
                    const cur = allSessions.find(s => s.id === currentSessionId);
                    if (cur && cur.status === 'completed') {
                        const sb = document.getElementById('scan-status-bar');
                        if (sb && sb.innerHTML.includes('Status: Running')) {
                            loadSessionDomains(currentSessionId, false);
                        }
                    }
                }
            }, 3000);
        } else if (!hasActive && sessionPollTimer) {
            clearInterval(sessionPollTimer);
            sessionPollTimer = null;
        }
    } catch (e) {
        console.error('fetchSessions error:', e);
        const c = document.getElementById('sessions-list');
        if (c) c.innerHTML = `<div class="text-red-400 text-center py-8 text-sm">Error loading sessions</div>`;
    }
}

function renderSessions() {
    const container = document.getElementById('sessions-list');
    if (!container) return;

    if (allSessions.length === 0) {
        container.innerHTML = `<div class="text-gray-500 text-center py-12 text-xs leading-relaxed">No scans yet.<br>Go to Scanner and start one.</div>`;
        return;
    }

    container.innerHTML = '';
    allSessions.forEach(s => renderSessionCard(s, container));
}

function renderSessionCard(s, container) {
    const isActive = currentSessionId === s.id;
    const status   = s.status;   // 'running' | 'paused' | 'completed'

    // Status indicator
    const statusBadge =
        status === 'running'   ? `<span class="flex items-center gap-1 text-amber-400 text-xs"><span class="w-1.5 h-1.5 bg-amber-400 rounded-full animate-pulse"></span>running</span>` :
        status === 'paused'    ? `<span class="flex items-center gap-1 text-sky-400 text-xs"><span class="w-1.5 h-1.5 bg-sky-400 rounded-full"></span>paused</span>` :
                                  `<span class="flex items-center gap-1 text-emerald-400 text-xs"><span class="w-1.5 h-1.5 bg-emerald-400 rounded-full"></span>done</span>`;

    const card = document.createElement('div');
    card.id = `session-card-${s.id}`;
    card.className = `session-item rounded-2xl text-sm ${isActive ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-800/60 bg-gray-800/30'} overflow-hidden`;

    // ── Top row: domain info (clickable to load results) ──
    const infoRow = document.createElement('div');
    infoRow.className = 'flex items-center justify-between px-4 pt-3 pb-2 cursor-pointer';
    infoRow.onclick = () => selectSession(s.id);
    infoRow.innerHTML = `
        <div class="flex-1 min-w-0">
            <div class="font-semibold truncate text-sm">${esc(s.domain)}</div>
            <div class="text-xs opacity-60 mt-0.5">${new Date(s.timestamp).toLocaleString()}</div>
        </div>
        <div class="ml-3 flex flex-col items-end gap-1">
            ${statusBadge}
            <div class="text-xs px-2 py-0.5 rounded-2xl bg-white/10 font-mono">${s.registered_count || 0} found</div>
        </div>`;
    card.appendChild(infoRow);

    // ── Control buttons row ──
    const ctrlRow = document.createElement('div');
    ctrlRow.className = 'flex gap-1.5 px-4 pb-3';

    // Pause button (shown when running)
    if (status === 'running') {
        ctrlRow.innerHTML += `
            <button onclick="sessionPause('${s.id}',event)"
                title="Pause this scan"
                class="flex-1 flex items-center justify-center gap-1.5 text-xs font-semibold
                       bg-amber-500/20 hover:bg-amber-500/40 text-amber-300 border border-amber-500/30
                       rounded-xl py-1.5 transition active:scale-95">
                <i class="fas fa-pause text-[10px]"></i> Pause
            </button>`;
    }

    // Resume button (shown when paused)
    if (status === 'paused') {
        ctrlRow.innerHTML += `
            <button onclick="sessionResume('${s.id}',event)"
                title="Resume from checkpoint"
                class="flex-1 flex items-center justify-center gap-1.5 text-xs font-semibold
                       bg-emerald-500/20 hover:bg-emerald-500/40 text-emerald-300 border border-emerald-500/30
                       rounded-xl py-1.5 transition active:scale-95">
                <i class="fas fa-play text-[10px]"></i> Resume
            </button>`;
    }

    // New scan button (shown when completed or paused – lets restart same domain)
    if (status === 'completed' || status === 'paused') {
        ctrlRow.innerHTML += `
            <button onclick="sessionNewScan('${s.domain}',event)"
                title="Start a new scan for ${esc(s.domain)}"
                class="flex-1 flex items-center justify-center gap-1.5 text-xs font-semibold
                       bg-blue-500/20 hover:bg-blue-500/40 text-blue-300 border border-blue-500/30
                       rounded-xl py-1.5 transition active:scale-95">
                <i class="fas fa-redo text-[10px]"></i> Re-scan
            </button>`;
    }

    // Reset / delete button (always)
    ctrlRow.innerHTML += `
        <button onclick="sessionReset('${s.id}',event)"
            title="Delete this session and all its results"
            class="flex items-center justify-center gap-1 text-xs font-semibold
                   bg-red-500/10 hover:bg-red-500/30 text-red-400 border border-red-500/20
                   rounded-xl px-2.5 py-1.5 transition active:scale-95">
            <i class="fas fa-trash-alt text-[10px]"></i>
        </button>`;

    card.appendChild(ctrlRow);
    container.appendChild(card);
}

// ── Session controls ─────────────────────────────────────────────────────────

async function sessionPause(sid, e) {
    e && e.stopPropagation();
    try {
        const r = await fetch(`/api/scans/${sid}/pause`, { method: 'POST' });
        const d = await r.json();
        if (d.error) { showToast(d.error); return; }
        showToast('⏸ Scan pausing…', 'warn');
        setTimeout(fetchSessions, 1200);
    } catch (err) { showToast('Pause failed: ' + err.message); }
}

async function sessionResume(sid, e) {
    e && e.stopPropagation();
    try {
        const r = await fetch(`/api/scans/${sid}/resume`, { method: 'POST' });
        const d = await r.json();
        if (d.error) { showToast(d.error); return; }
        showToast('▶ Scan resumed from checkpoint', 'success');
        setTimeout(fetchSessions, 800);
        // Start auto-refresh if this is the selected session
        if (currentSessionId === sid) {
            if (!sessionPollTimer) {
                sessionPollTimer = setInterval(() => {
                    fetchSessions();
                    loadSessionDomains(currentSessionId, false);
                }, 3000);
            }
        }
    } catch (err) { showToast('Resume failed: ' + err.message); }
}

async function sessionReset(sid, e) {
    e && e.stopPropagation();
    const s = allSessions.find(x => x.id === sid);
    const label = s ? s.domain : sid.substring(0, 8);
    // Removed native confirm() dialog because embedded browsers block it silently
    try {
        await fetch(`/api/scans/${sid}/reset`, { method: 'POST' });
        showToast(`🗑 Session "${label}" cleared`, 'success');
        if (currentSessionId === sid) {
            currentSessionId = null;
            document.getElementById('current-session-badge').classList.add('hidden');
            loadGlobalDashboard();
        }
        fetchSessions();
    } catch (err) { showToast('Reset failed: ' + err.message); }
}

async function sessionNewScan(domain, e) {
    e && e.stopPropagation();

    // Find the button that was clicked and show a spinner
    const btn = e && e.currentTarget;
    const originalHTML = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin text-[10px]"></i>';
    }

    try {
        const res = await fetch('/api/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        const data = await res.json();

        if (data.error) {
            showToast('❌ ' + data.error);
            if (btn) { btn.disabled = false; btn.innerHTML = originalHTML; }
            return;
        }

        showToast(`🚀 New scan started for ${domain}`);

        // Refresh sessions list so the new session appears, then select it
        await fetchSessions();
        if (data.id) selectSession(data.id);

    } catch (err) {
        showToast('❌ Failed to start scan');
        if (btn) { btn.disabled = false; btn.innerHTML = originalHTML; }
    }
}

// ── Select a session → show its isolated phishing domain list ────────────────
let _sessionLoadController = null;  // AbortController for cancelling in-flight requests

async function selectSession(sid) {
    // Cancel any in-flight session load
    if (_sessionLoadController) _sessionLoadController.abort();
    _sessionLoadController = new AbortController();

    currentSessionId = sid;

    // Highlight selected card immediately
    document.querySelectorAll('.session-item').forEach(el => {
        el.classList.remove('bg-blue-600', 'text-white');
        el.classList.add('text-gray-300', 'hover:bg-gray-800/60', 'bg-gray-800/30');
    });
    const card = document.getElementById(`session-card-${sid}`);
    if (card) {
        card.classList.add('bg-blue-600', 'text-white');
        card.classList.remove('text-gray-300', 'hover:bg-gray-800/60', 'bg-gray-800/30');
    }

    // Clear the domain table immediately so stale data isn't visible
    const tbody = document.getElementById('domains-body');
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="px-8 py-16 text-center text-gray-500 animate-pulse">Loading session data…</td></tr>`;

    // Find session from cache OR fetch fresh
    let session = allSessions.find(s => s.id === sid);
    if (!session) {
        try {
            const r = await fetch(`/api/scans/${sid}/status`, { signal: _sessionLoadController.signal });
            const st = await r.json();
            session = { id: sid, domain: st.domain || sid, status: st.status };
        } catch (_) {}
    }

    const badge = document.getElementById('current-session-badge');
    if (badge && session) {
        badge.textContent = `${session.domain} • ${sid.substring(0, 8)}`;
        badge.classList.remove('hidden');
    }

    // Update header title
    const title = document.getElementById('current-page-title');
    if (title && session) {
        title.textContent = `${session.domain} — Phishing Domains`;
    }

    // Update URL hash so the link is shareable
    history.replaceState(null, '', `/dashboard#${sid}`);

    await loadSessionDomains(sid, false);
}

async function loadSessionDomains(sid, switchToDomainsTab = false) {
    try {
        const [domainsRes, statusRes] = await Promise.all([
            fetch(`/api/scans/${sid}/domains`),
            fetch(`/api/scans/${sid}/status`)
        ]);

        // If the user switched away while we were loading, discard this result
        if (currentSessionId !== sid) return;

        const domains = await domainsRes.json();
        const status  = await statusRes.json();

        const safe      = domains.filter(d => d.risk_status === 'Safe').length;
        const suspicious = domains.filter(d => d.risk_status === 'Suspicious').length;
        const malicious  = domains.filter(d => d.risk_status === 'Malicious').length;

        renderRiskCards({ safe, suspicious, malicious });
        renderRiskChart({ safe, suspicious, malicious });
        renderDomainsTable(domains, sid);
        renderRecentTable([...domains].reverse().slice(0, 20));  // NEW: Fill the recent-table on the Overview tab!
        renderSessionAlerts(sid);

        renderTabs(false); // Render session-specific tabs

        // Show scan-status bar above the domain table
        renderScanStatusBar(status);

        if (switchToDomainsTab) switchTab(domains.length > 0 ? 1 : 0);
    } catch (e) {
        if (e.name === 'AbortError') return;  // intentionally cancelled
        console.error('loadSessionDomains error:', e);
        showToast('❌ Failed to load session data');
    }
}


// ── Scan progress bar shown inside main panel when selected ──────────────────
function renderScanStatusBar(status) {
    let bar = document.getElementById('scan-status-bar');
    if (!bar) {
        bar = document.createElement('div');
        bar.id = 'scan-status-bar';
        bar.className = 'mb-6';
        const tabArea = document.querySelector('.p-8');
        if (tabArea) tabArea.prepend(bar);
    }

    if (!status || status.status === 'completed') {
        bar.innerHTML = '';
        return;
    }

    const isRunning  = status.status === 'running';
    const isPaused   = status.status === 'paused';
    const pct        = Math.min(status.progress_pct || 0, 100);
    const total      = status.total_permutations || 0;
    const done       = status.registered_count   || 0;
    const phase      = status.phase || 'dns';

    const phaseLabel =
        phase === 'dns'        ? `🔍 Phase 1/2 — DNS Resolution` :
        phase === 'enrichment' ? `⚡ Phase 2/2 — Threat Enrichment` :
                                  'Processing…';

    const dnsDone  = status.dns_done  || 0;
    const dnsTotal = status.dns_total || total || 0;

    const phaseDetail =
        phase === 'dns'
            ? (dnsTotal > 0 ? `${dnsDone} of ${dnsTotal} domains resolved` : 'Resolving DNS…')
            : phase === 'enrichment'
            ? `${done} threats found and saved`
            : '';

    const barColor = isPaused  ? 'bg-amber-500' :
                     pct >= 75  ? 'bg-emerald-500' :
                                  'bg-blue-500';

    bar.innerHTML = `
        <div class="${isPaused ? 'bg-amber-500/10 border-amber-500/30' : 'bg-gray-800 border-gray-700'}
                    border rounded-2xl px-6 py-5">

            <!-- Top row -->
            <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-3">
                    ${isRunning
                        ? `<div class="relative"><div class="w-3 h-3 bg-blue-400 rounded-full animate-ping absolute"></div><div class="w-3 h-3 bg-blue-400 rounded-full"></div></div>`
                        : `<i class="fas fa-pause text-amber-400"></i>`}
                    <div>
                        <div class="font-semibold text-sm ${isPaused ? 'text-amber-300' : 'text-white'}">
                            ${isPaused ? '⏸ Scan Paused' : phaseLabel}
                        </div>
                        <div class="text-xs text-gray-400 mt-0.5">${isPaused ? 'Click Resume to continue from checkpoint' : phaseDetail}</div>
                    </div>
                </div>

                <!-- Controls -->
                <div class="flex items-center gap-2">
                    ${isPaused ? `
                        <button onclick="sessionResume('${currentSessionId}',null)"
                            class="text-xs font-semibold bg-emerald-500/20 hover:bg-emerald-500/40 text-emerald-300
                                   border border-emerald-500/30 rounded-xl px-4 py-2 transition flex items-center gap-1.5">
                            <i class="fas fa-play text-[10px]"></i> Resume
                        </button>` : `
                        <button onclick="sessionPause('${currentSessionId}',null)"
                            class="text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/40 text-amber-300
                                   border border-amber-500/30 rounded-xl px-4 py-2 transition flex items-center gap-1.5">
                            <i class="fas fa-pause text-[10px]"></i> Pause
                        </button>`}
                    <button onclick="sessionReset('${currentSessionId}',null)"
                        class="text-xs font-semibold bg-red-500/10 hover:bg-red-500/30 text-red-400
                               border border-red-500/20 rounded-xl px-3 py-2 transition flex items-center gap-1">
                        <i class="fas fa-trash-alt text-[10px]"></i>
                    </button>
                </div>
            </div>

            <!-- Progress bar -->
            <div class="space-y-1">
                <div class="flex justify-between text-xs mb-1">
                    <span class="text-gray-400">
                        ${total > 0 ? `${done} threats found of ~${total} permutations` : `${done} threats found`}
                    </span>
                    <span class="font-semibold ${isPaused ? 'text-amber-400' : 'text-blue-400'}">${pct.toFixed(1)}%</span>
                </div>
                <div class="h-2.5 bg-gray-700 rounded-full overflow-hidden">
                    <div class="h-full ${barColor} rounded-full progress-fill ${isRunning ? 'transition-all duration-1000' : ''}"
                         style="width: ${pct}%"></div>
                </div>
                <!-- Phase markers -->
                <div class="flex justify-between text-[10px] text-gray-600 mt-1 px-0.5">
                    <span>Start</span>
                    <span class="${phase === 'enrichment' ? 'text-blue-500' : 'text-gray-600'}" style="position:relative;left:0">Enrichment ▸</span>
                    <span>Done</span>
                </div>
            </div>
        </div>`;
}

// ── Domain Detail Modal ───────────────────────────────────────────────────────

async function openDomainModal(domainName, sid) {
    const overlay = document.getElementById('domain-modal-overlay');
    const panel   = document.getElementById('domain-modal-panel');
    if (!overlay || !panel) return;

    // Show modal immediately with loading state
    overlay.classList.remove('hidden');
    panel.classList.remove('hidden');
    panel.classList.add('flex');
    document.body.style.overflow = 'hidden';

    // Reset fields
    document.getElementById('modal-domain-name').textContent = domainName;
    document.getElementById('modal-risk-badge').textContent = '—';
    document.getElementById('modal-score-text').textContent = 'Loading…';
    document.getElementById('modal-score-bar').style.width = '0%';
    document.getElementById('modal-score-val').textContent = '—';
    document.getElementById('modal-vt-section').innerHTML = '<div class="text-gray-500 text-sm animate-pulse">Fetching threat intelligence…</div>';
    document.getElementById('modal-whois').innerHTML = '<div class="text-gray-500 text-sm animate-pulse col-span-2">Loading WHOIS…</div>';
    document.getElementById('modal-ssl').innerHTML = '<div class="text-gray-500 text-sm animate-pulse">Loading SSL…</div>';
    document.getElementById('modal-dns').innerHTML = '<div class="text-gray-500 text-sm animate-pulse">Loading DNS…</div>';
    document.getElementById('modal-web').innerHTML = '<div class="text-gray-500 text-sm animate-pulse">Loading web…</div>';

    // Reset takedown button state immediately
    const takedownBtn = document.getElementById('modal-takedown-btn');
    if (takedownBtn) {
        takedownBtn.style.display = 'none';
        takedownBtn.className = 'bg-blue-600 hover:bg-blue-500 text-white text-[11px] font-bold px-3 py-1.5 rounded-lg transition-all whitespace-nowrap';
        takedownBtn.innerHTML = '<i class="fas fa-bell mr-1"></i>Notify Brand Owner';
        takedownBtn.disabled = false;
    }

    try {
        const res  = await fetch(`/api/scans/${sid}/domains/${encodeURIComponent(domainName)}`);
        const data = await res.json();
        if (data.error) { showToast('❌ ' + data.error); closeDomainModal(); return; }
        populateDomainModal(data);
    } catch (e) {
        showToast('❌ Failed to load domain details');
        closeDomainModal();
    }
}

function closeDomainModal() {
    const overlay = document.getElementById('domain-modal-overlay');
    const panel   = document.getElementById('domain-modal-panel');
    if (overlay) overlay.classList.add('hidden');
    if (panel)   { panel.classList.add('hidden'); panel.classList.remove('flex'); }
    document.body.style.overflow = '';
}

function populateDomainModal(data) {
    // Header
    document.getElementById('modal-domain-name').textContent = data.domain;
    const riskBadge = document.getElementById('modal-risk-badge');
    riskBadge.textContent = `${data.risk_emoji} ${data.risk_status}`;
    riskBadge.className = `px-3 py-1 text-xs font-semibold rounded-full ` +
        (data.risk_status === 'Malicious'  ? 'bg-red-500/20 text-red-400' :
         data.risk_status === 'Suspicious' ? 'bg-amber-500/20 text-amber-400' :
                                             'bg-emerald-500/20 text-emerald-400');

    document.getElementById('modal-score-text').textContent = `Score: ${data.risk_score}/100`;

    // Takedown button visibility
    const takedownBtn = document.getElementById('modal-takedown-btn');
    if (takedownBtn) {
        if (data.risk_status === 'Malicious') {
            takedownBtn.style.display = 'inline-flex';
            takedownBtn.style.alignItems = 'center';
        } else {
            takedownBtn.style.display = 'none';
        }
    }

    // Action badge
    const actionBadge = document.getElementById('modal-action-badge');
    if (actionBadge && data.risk_action) {
        actionBadge.textContent = data.risk_action;
        actionBadge.className = 'px-3 py-1 text-xs font-medium rounded-full border ' +
            (data.risk_status === 'Malicious'  ? 'border-red-500/40 text-red-400 bg-red-500/10' :
             data.risk_status === 'Suspicious' ? 'border-amber-500/40 text-amber-400 bg-amber-500/10' :
                                                 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10');
        actionBadge.classList.remove('hidden');
    }

    // VT header badge
    const vtHeaderBadge = document.getElementById('modal-vt-badge');
    const vt = data.virustotal || {};
    if (vt.available && vt.malicious > 0) {
        vtHeaderBadge.textContent = `⚠ ${vt.malicious} engines flagged`;
        vtHeaderBadge.classList.remove('hidden');
    }



    // Score bar — use adaptive thresholds (52/22 when no VT, 75/28 with VT)
    const score    = data.risk_score || 0;
    const vtAvail  = (data.virustotal || {}).available;
    const tMal     = vtAvail ? 75 : 52;
    const tSus     = vtAvail ? 28 : 22;
    const barEl    = document.getElementById('modal-score-bar');
    const valEl    = document.getElementById('modal-score-val');
    // Update gauge labels
    const elSus = document.getElementById('modal-thresh-sus');
    const elMal = document.getElementById('modal-thresh-mal');
    if (elSus) elSus.textContent = `${tSus} — Suspicious`;
    if (elMal) elMal.textContent = `${tMal}–100 — Malicious`;

    valEl.textContent = score;
    valEl.className = `font-bold text-2xl ${score >= tMal ? 'text-red-400' : score >= tSus ? 'text-amber-400' : 'text-emerald-400'}`;
    barEl.className  = `h-full rounded-full transition-all duration-700 ${score >= tMal ? 'bg-red-500' : score >= tSus ? 'bg-amber-500' : 'bg-emerald-500'}`;
    setTimeout(() => { barEl.style.width = score + '%'; }, 50);

    // Per-signal breakdown bars
    const breakdownEl = document.getElementById('modal-score-breakdown');
    if (breakdownEl) {
        const bd = data.score_breakdown || {};
        const ORDER = ['ml','vt','age','sim','struct','content','ssl'];
        const ICONS = {
            ml:      {icon: 'fa-robot',        color: 'blue'},
            vt:      {icon: 'fa-shield-virus',  color: 'purple'},
            age:     {icon: 'fa-calendar-alt',  color: 'yellow'},
            sim:     {icon: 'fa-eye',           color: 'orange'},
            struct:  {icon: 'fa-code',          color: 'cyan'},
            content: {icon: 'fa-file-alt',      color: 'pink'},
            ssl:     {icon: 'fa-lock',          color: 'teal'},
        };
        if (Object.keys(bd).length === 0) {
            breakdownEl.innerHTML = '<p class="text-xs text-gray-500">Breakdown not available</p>';
        } else {
            breakdownEl.innerHTML = ORDER.map(key => {
                const sig  = bd[key] || {pts: 0, max: 0, label: key};
                const pct  = sig.max > 0 ? Math.round((sig.pts / sig.max) * 100) : 0;
                const info  = ICONS[key] || {icon:'fa-circle', color:'gray'};
                const barColor = sig.pts === 0 ? 'bg-gray-600'
                               : sig.pts >= sig.max * 0.75 ? 'bg-red-500'
                               : sig.pts >= sig.max * 0.4  ? 'bg-amber-500'
                               :                             'bg-emerald-500';
                const prob = (key === 'ml' && sig.prob != null)
                    ? `<span class="text-gray-500 text-xs ml-1">(${(sig.prob * 100).toFixed(0)}% phish)</span>` : '';
                return `
                <div class="flex items-center gap-3 group">
                    <div class="w-5 text-center flex-shrink-0">
                        <i class="fas ${info.icon} text-${info.color}-400 text-xs opacity-70 group-hover:opacity-100"></i>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="flex justify-between items-center mb-0.5">
                            <span class="text-xs text-gray-300">${esc(sig.label)}${prob}</span>
                            <span class="text-xs font-mono ${ sig.pts > 0 ? (sig.pts >= sig.max * 0.75 ? 'text-red-400' : 'text-amber-400') : 'text-gray-500' }">
                                ${sig.pts}/${sig.max}
                            </span>
                        </div>
                        <div class="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                            <div class="h-full ${barColor} rounded-full transition-all duration-700" style="width:0%" data-pct="${pct}"></div>
                        </div>
                    </div>
                </div>`;
            }).join('');
            // Animate bars after paint
            setTimeout(() => {
                breakdownEl.querySelectorAll('[data-pct]').forEach(el => {
                    el.style.width = el.dataset.pct + '%';
                });
            }, 80);
        }
    }

    // VirusTotal section
    const vtSection = document.getElementById('modal-vt-section');
    if (!vt.available) {
        vtSection.innerHTML = `
            <div class="flex items-center gap-3 text-gray-400 text-sm">
                <i class="fas fa-info-circle text-blue-400 text-lg"></i>
                <div>
                    <div class="font-medium text-white">VirusTotal not available</div>
                    <div class="text-xs mt-0.5">${esc(vt.reason || 'API key not configured')}</div>
                    <div class="text-xs mt-1 text-blue-400">Add VIRUSTOTAL_API_KEY to .env to enable this feature</div>
                </div>
            </div>`;
    } else {
        const total   = vt.engines_total || 1;
        const malPct  = Math.round((vt.malicious / total) * 100);
        const susPct  = Math.round((vt.suspicious / total) * 100);
        const harmPct = Math.round((vt.harmless   / total) * 100);
        const comScore = vt.community_score || 0;
        const comClass = comScore < -5 ? 'text-red-400' : comScore > 5 ? 'text-emerald-400' : 'text-gray-400';
        vtSection.innerHTML = `
            <div class="grid grid-cols-4 gap-4 mb-5">
                <div class="text-center bg-red-500/10 rounded-xl p-3">
                    <div class="text-2xl font-bold text-red-400">${vt.malicious}</div>
                    <div class="text-xs text-gray-400 mt-1">Malicious</div>
                </div>
                <div class="text-center bg-amber-500/10 rounded-xl p-3">
                    <div class="text-2xl font-bold text-amber-400">${vt.suspicious}</div>
                    <div class="text-xs text-gray-400 mt-1">Suspicious</div>
                </div>
                <div class="text-center bg-emerald-500/10 rounded-xl p-3">
                    <div class="text-2xl font-bold text-emerald-400">${vt.harmless}</div>
                    <div class="text-xs text-gray-400 mt-1">Harmless</div>
                </div>
                <div class="text-center bg-gray-700/50 rounded-xl p-3">
                    <div class="text-2xl font-bold ${comClass}">${comScore > 0 ? '+' : ''}${comScore}</div>
                    <div class="text-xs text-gray-400 mt-1">Community</div>
                </div>
            </div>
            <!-- Engine coverage bar -->
            <div class="mb-4">
                <div class="text-xs text-gray-400 mb-1">${total} engines scanned</div>
                <div class="h-2 bg-gray-700 rounded-full overflow-hidden flex">
                    <div class="h-full bg-red-500" style="width:${malPct}%"></div>
                    <div class="h-full bg-amber-500" style="width:${susPct}%"></div>
                    <div class="h-full bg-emerald-500" style="width:${harmPct}%"></div>
                </div>
                <div class="flex gap-4 text-[10px] text-gray-500 mt-1">
                    <span class="text-red-400">■ ${malPct}% malicious</span>
                    <span class="text-amber-400">■ ${susPct}% suspicious</span>
                    <span class="text-emerald-400">■ ${harmPct}% harmless</span>
                </div>
            </div>
            ${vt.flagging_engines && vt.flagging_engines.length > 0 ? `
            <div>
                <div class="text-xs text-gray-400 mb-2">Flagging engines:</div>
                <div class="flex flex-wrap gap-2">
                    ${vt.flagging_engines.map(e => `<span class="px-2 py-0.5 bg-red-500/15 text-red-400 text-xs rounded-lg">${esc(e)}</span>`).join('')}
                </div>
            </div>` : ''}`;
    }
    // VT link
    const vtLink = document.getElementById('modal-vt-link');
    if (vtLink) vtLink.href = vt.vt_link || `https://www.virustotal.com/gui/domain/${esc(data.domain)}`;

    // WHOIS
    const w = data.whois || {};
    document.getElementById('modal-whois').innerHTML = `
        ${whoisRow('Registrar',      w.registrar)}
        ${whoisRow('Created',        w.creation_date)}
        ${whoisRow('Expires',        w.expiration_date)}
        ${whoisRow('Domain Age',     w.age_days != null ? w.age_days + ' days' : '—')}`;

    // SSL
    const ssl = data.ssl || {};
    const sslColor  = ssl.valid ? 'text-emerald-400' : 'text-red-400';
    const sslIcon   = ssl.valid ? 'fa-lock'          : 'fa-lock-open';
    document.getElementById('modal-ssl').innerHTML = `
        <div class="flex items-center gap-3 mb-3">
            <i class="fas ${sslIcon} text-xl ${sslColor}"></i>
            <span class="font-semibold ${sslColor}">${ssl.valid ? 'Valid SSL Certificate' : 'No Valid SSL'}</span>
        </div>
        ${ssl.valid ? `
        <div class="space-y-1 text-gray-400 text-xs">
            <div><span class="text-gray-500">Issuer: </span>${esc(ssl.issuer||'—')}</div>
            <div><span class="text-gray-500">Expires: </span>${esc(ssl.expires||'—')}</div>
        </div>` : '<div class="text-xs text-gray-500">No HTTPS or certificate invalid/self-signed</div>'}`;

    // DNS
    const dns_a  = data.dns_a  || [];
    const dns_mx = data.dns_mx || [];
    const dns_ns = data.dns_ns || [];
    document.getElementById('modal-dns').innerHTML = `
        <div class="space-y-3">
            <div>
                <div class="text-gray-500 text-xs mb-1">A Records (IPs) ${dns_a.length > 3 ? '<span class="text-amber-400">⚠ many IPs = possible fast-flux</span>' : ''}</div>
                <div class="flex flex-wrap gap-2">${dns_a.length ? dns_a.map(ip=>`<code class="px-2 py-0.5 bg-gray-700 rounded text-xs text-cyan-300">${esc(ip)}</code>`).join('') : '<span class="text-gray-600">none</span>'}</div>
            </div>
            <div>
                <div class="text-gray-500 text-xs mb-1">MX Records (mail)</div>
                <div class="flex flex-wrap gap-2">${dns_mx.length ? dns_mx.map(mx=>`<code class="px-2 py-0.5 bg-gray-700 rounded text-xs text-purple-300">${esc(mx)}</code>`).join('') : '<span class="text-gray-600">none — no email capability</span>'}</div>
            </div>
            <div>
                <div class="text-gray-500 text-xs mb-1">NS Records (nameservers)</div>
                <div class="flex flex-wrap gap-2">${dns_ns.length ? dns_ns.map(ns=>`<code class="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300">${esc(ns)}</code>`).join('') : '<span class="text-gray-600">none</span>'}</div>
            </div>
            ${data.fuzzer ? `<div class="text-xs text-gray-500">Fuzzer type: <span class="text-blue-400">${esc(data.fuzzer)}</span></div>` : ''}
        </div>`;

    // Web
    const web = data.web || {};
    const httpsOk = web.https_status === 200;
    document.getElementById('modal-web').innerHTML = `
        <div class="space-y-3">
            <div class="flex items-start gap-3">
                <span class="px-2 py-0.5 text-xs rounded font-mono ${httpsOk ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-400'}">${web.https_status || 'N/A'}</span>
                <div>
                    <div class="font-medium text-white text-sm">${esc(web.https_title || 'No title')}</div>
                    <div class="text-xs text-gray-500 mt-0.5 break-all">${esc(web.https_url || '—')}</div>
                </div>
            </div>
        </div>`;
}

function whoisRow(label, value) {
    return `
        <div>
            <div class="text-gray-500 text-xs">${label}</div>
            <div class="text-white font-mono text-sm mt-0.5 break-all">${esc(value||'—')}</div>
        </div>`;
}

// ── Global dashboard (no session selected) ───────────────────────────────────
async function loadGlobalDashboard() {
    currentSessionId = null;
    const badge = document.getElementById('current-session-badge');
    if (badge) badge.classList.add('hidden');
    const title = document.getElementById('current-page-title');
    if (title) title.textContent = 'Threat Intelligence Dashboard';

    // Clear scan-status bar
    const bar = document.getElementById('scan-status-bar');
    if (bar) bar.innerHTML = '';

    try {
        renderTabs(true); // Render global tabs
        
        const res  = await fetch('/api/dashboard');
        const data = await res.json();
        renderRiskCards(data.risk_overview);
        renderRiskChart(data.risk_overview);
        renderRecentTable(data.detected_domains);
        renderAlertsGlobal(data.recent_alerts);
    } catch (e) { console.error('Global dashboard error:', e); }
}

// ── Render: risk cards ────────────────────────────────────────────────────────
function renderRiskCards(ov) {
    const c = document.getElementById('risk-cards');
    if (!c) return;

    // Pluck values
    const safeNum = ov.safe || 0;
    const suspNum = ov.suspicious || 0;
    const malNum = ov.malicious || 0;

    // Check if cards already exist to avoid hard DOM wipes
    const existingSafe = c.querySelector('#card-val-safe');
    if (existingSafe) {
        updateNumberAnimation(existingSafe, safeNum);
        updateNumberAnimation(c.querySelector('#card-val-suspicious'), suspNum);
        updateNumberAnimation(c.querySelector('#card-val-malicious'), malNum);
        return;
    }

    c.innerHTML = `
        <div class="card bg-emerald-600/10 border border-emerald-500/40 rounded-3xl p-6">
            <div class="flex justify-between items-start">
                <div><div class="text-emerald-400 text-xs font-semibold tracking-widest uppercase">Safe</div>
                <div id="card-val-safe" class="text-5xl font-bold text-emerald-400 mt-2 transition-transform duration-300 ease-out">${safeNum}</div></div>
                <i class="fas fa-check-circle text-5xl text-emerald-400 opacity-40"></i>
            </div>
        </div>
        <div class="card bg-amber-600/10 border border-amber-500/40 rounded-3xl p-6">
            <div class="flex justify-between items-start">
                <div><div class="text-amber-400 text-xs font-semibold tracking-widest uppercase">Suspicious</div>
                <div id="card-val-suspicious" class="text-5xl font-bold text-amber-400 mt-2 transition-transform duration-300 ease-out">${suspNum}</div></div>
                <i class="fas fa-exclamation-triangle text-5xl text-amber-400 opacity-40"></i>
            </div>
        </div>
        <div class="card bg-red-600/10 border border-red-500/40 rounded-3xl p-6">
            <div class="flex justify-between items-start">
                <div><div class="text-red-400 text-xs font-semibold tracking-widest uppercase">Malicious</div>
                <div id="card-val-malicious" class="text-5xl font-bold text-red-400 mt-2 transition-transform duration-300 ease-out">${malNum}</div></div>
                <i class="fas fa-skull-crossbones text-5xl text-red-400 opacity-40"></i>
            </div>
        </div>`;
}

function updateNumberAnimation(el, newval) {
    if (!el || parseInt(el.innerText) === newval) return;
    el.style.transform = 'scale(1.2)';
    el.innerText = newval;
    setTimeout(() => {
        el.style.transform = 'scale(1)';
    }, 150);
}

// ── Render: doughnut chart ────────────────────────────────────────────────────
function renderRiskChart(ov) {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;
    const total = (ov.safe||0) + (ov.suspicious||0) + (ov.malicious||0);
    if (total === 0) {
        if (riskChartInstance) { riskChartInstance.destroy(); riskChartInstance = null; }
        ctx.parentElement.innerHTML = `<h3 class="text-xl font-semibold mb-6">Risk Overview</h3><p class="text-gray-500 text-center py-16">No data yet. Select a session to see results.</p>`;
        return;
    }
    
    // If it exists, natively bump the values to trigger ChartJS fluid animations
    if (riskChartInstance) {
        riskChartInstance.data.datasets[0].data = [ov.safe||0, ov.suspicious||0, ov.malicious||0];
        riskChartInstance.update();
        return;
    }
    
    // Create Premium Gradients
    const canvasCtx = ctx.getContext('2d');
    const gradSafe = canvasCtx.createLinearGradient(0, 0, 0, 180);
    gradSafe.addColorStop(0, '#34d399'); gradSafe.addColorStop(1, '#059669');
    
    const gradSusp = canvasCtx.createLinearGradient(0, 0, 0, 180);
    gradSusp.addColorStop(0, '#fbbf24'); gradSusp.addColorStop(1, '#b45309');
    
    const gradMal = canvasCtx.createLinearGradient(0, 0, 0, 180);
    gradMal.addColorStop(0, '#f87171'); gradMal.addColorStop(1, '#991b1b');

    riskChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe','Suspicious','Malicious'],
            datasets: [{ 
                data: [ov.safe||0, ov.suspicious||0, ov.malicious||0],
                backgroundColor: [gradSafe, gradSusp, gradMal],
                hoverBackgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                borderColor: '#111827', 
                borderWidth: 4,
                hoverOffset: 8
            }]
        },
        options: {
            cutout: '82%',
            layout: { padding: 10 },
            animation: { animateScale: true, animateRotate: true, duration: 800, easing: 'easeOutQuart' },
            plugins: { 
                legend: { position: 'bottom', labels: { color:'#e5e7eb', usePointStyle: true, boxWidth: 10, padding: 25, font: { size: 13, family: "'Inter', sans-serif" } } },
                tooltip: { backgroundColor: 'rgba(17, 24, 39, 0.9)', titleColor: '#fff', bodyColor: '#cbd5e1', padding: 12, cornerRadius: 8, borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1 }
            }
        }
    });
}

// ── Render: domains table (isolated per session) ─────────────────────────────
function renderDomainsTable(domains, sid) {
    const tbody = document.getElementById('domains-body');
    if (!tbody) return;

    if (!domains || domains.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="px-8 py-16 text-center text-gray-500">
            No phishing domains detected yet for this session.${
            allSessions.find(s=>s.id===sid)?.status==='running' ? '<br><span class="text-blue-400 text-xs mt-1 block">Scan is running — results appear here in real-time.</span>' : ''
            }</td></tr>`;
        return;
    }

    tbody.innerHTML = domains.map(d => {
        // VT badge
        let vtBadge = '';
        if (d.vt_available && d.vt_malicious > 0) {
            vtBadge = `<span class="ml-2 px-1.5 py-0.5 text-[10px] font-bold rounded bg-red-500/20 text-red-400" title="VirusTotal: ${d.vt_malicious} engines flagged">
                VT:${d.vt_malicious}⚠
            </span>`;
        } else if (d.vt_available) {
            vtBadge = `<span class="ml-2 px-1.5 py-0.5 text-[10px] rounded bg-emerald-500/10 text-emerald-500" title="VirusTotal: clean">VT✓</span>`;
        }
        return `
        <tr class="hover:bg-gray-800/50 transition-colors cursor-pointer group"
            onclick="openDomainModal('${esc(d.domain)}', '${sid}')">
            <td class="px-8 py-5 font-medium font-mono text-sm">
                ${esc(d.domain)}${vtBadge}
            </td>
            <td class="px-8 py-5">
                <span class="inline-flex items-center gap-2 font-semibold text-sm
                    ${d.risk_status==='Malicious' ? 'text-red-400' : d.risk_status==='Suspicious' ? 'text-amber-400' : 'text-emerald-400'}">
                    ${d.risk_emoji||'🟢'} ${d.risk_status||'Safe'}
                </span>
            </td>
            <td class="px-8 py-5 font-mono text-sm">${d.risk_score??'—'}</td>
            <td class="px-8 py-5 text-sm text-center">${d.age_days??'—'}</td>
            <td class="px-8 py-5 text-gray-400 text-sm truncate">${esc(d.web_title??'—')}</td>
            <td class="px-8 py-5 font-mono text-center text-sm">${esc(d.ip??'—')}</td>
            <td class="px-8 py-5 text-right">
                <span class="text-xs text-blue-400 opacity-0 group-hover:opacity-100 transition inline-flex justify-end items-center gap-1">
                    <i class="fas fa-search-plus"></i> Details
                </span>
            </td>
        </tr>`;
    }).join('');
}

// ── Render: recent activity (global overview) ─────────────────────────────────
function renderRecentTable(domains) {
    const c = document.getElementById('recent-table');
    if (!c) return;
    if (!domains || domains.length === 0) {
        c.innerHTML = `<p class="text-gray-500 text-center py-12 text-sm">No domains yet. Start a scan.</p>`;
        return;
    }
    c.innerHTML = `<table class="w-full text-sm table-fixed">
        <thead><tr class="text-gray-400 text-[10px] uppercase tracking-wider">
            <th class="text-left py-3 w-[38%]">Domain</th>
            <th class="text-left py-3 w-[26%]">Risk</th>
            <th class="text-center py-3 w-[12%]">Score</th>
            <th class="text-right py-3 w-[24%]">Time</th>
        </tr></thead><tbody>
        ${domains.map(d => `<tr class="border-b border-gray-800 hover:bg-gray-800/30">
            <td class="py-4 font-mono text-xs truncate pr-2">${esc(d.domain)}</td>
            <td><span class="px-3 py-1 text-[10px] uppercase font-bold tracking-wider rounded-3xl ${
                d.risk_status==='Malicious' ? 'bg-red-500/20 text-red-400' :
                d.risk_status==='Suspicious' ? 'bg-amber-500/20 text-amber-400' :
                'bg-emerald-500/20 text-emerald-400'}">${d.risk_status}</span></td>
            <td class="font-medium text-center text-xs opacity-90">${d.risk_score}</td>
            <td class="text-gray-500 text-[11px] text-right truncate pl-2">${new Date(d.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
        </tr>`).join('')}
        </tbody></table>`;
}

// ── Render: alerts (per session) ─────────────────────────────────────────────
async function renderSessionAlerts(sid) {
    const c = document.getElementById('alerts-list');
    if (!c) return;
    try {
        const res  = await fetch('/api/dashboard');
        const data = await res.json();
        renderAlertsGlobal(data.recent_alerts);
    } catch (e) { c.innerHTML = `<p class="text-red-400 text-center py-12">Error loading alerts</p>`; }
}

function renderAlertsGlobal(alerts) {
    const c = document.getElementById('alerts-list');
    if (!c) return;
    if (!alerts || alerts.length === 0) {
        c.innerHTML = `<p class="text-gray-500 text-center py-16">No alerts yet. High-risk detections will appear here.</p>`;
        return;
    }
    c.innerHTML = alerts.map(a => `
        <div class="flex items-center justify-between bg-gray-800/70 rounded-2xl px-6 py-4 border border-red-500/20">
            <div class="flex items-center gap-4">
                <i class="fas fa-exclamation-triangle text-red-400 text-xl"></i>
                <div>
                    <div class="font-mono text-sm">${esc(a.domain)}</div>
                    <div class="text-sm text-gray-400 mt-0.5">${esc(a.message)}</div>
                </div>
            </div>
            <span class="px-4 py-1 text-xs bg-red-500/20 text-red-400 rounded-3xl font-medium ml-4">${a.severity}</span>
        </div>`).join('');
}

// ── Tab switching & Context ───────────────────────────────────────────────────
function renderTabs(isGlobal) {
    const container = document.getElementById('tab-header-container');
    if (!container) return;

    if (isGlobal) {
        container.innerHTML = `
            <button onclick="switchTab(0)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="0">Overview</button>
            <button onclick="switchTab(2)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="2">Global Alerts</button>
            <button onclick="switchTab(3)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="3">Platform Reports</button>
        `;
    } else {
        container.innerHTML = `
            <button onclick="switchTab(0)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="0">Session Overview</button>
            <button onclick="switchTab(1)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="1">Detected Domains</button>
            <button onclick="switchTab(4)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="4">Session Logs</button>
            <button onclick="switchTab(3)" class="tab-button px-8 py-4 font-medium text-base border-b-2 border-transparent text-gray-400 hover:text-gray-300 transition-colors" data-target="3">Session Reports</button>
        `;
    }

    // Attempt to keep existing tab if it's available in new context, else fallback to 0
    let currentActive = 0;
    const activeEl = document.querySelector('.tab-content:not(.hidden)');
    if (activeEl) {
        const idMatches = activeEl.id.match(/tab-(\d+)/);
        if (idMatches && container.querySelector(`[data-target="${idMatches[1]}"]`)) {
            currentActive = parseInt(idMatches[1]);
        }
    }
    switchTab(currentActive);
}

function switchTab(tabIndex) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    
    // Show target content
    const t = document.getElementById(`tab-${tabIndex}`);
    if (t) t.classList.remove('hidden');

    // Update active state based on data-target attribute of the currently rendered buttons
    document.querySelectorAll('#tab-header-container .tab-button').forEach(btn => {
        if (parseInt(btn.getAttribute('data-target')) === tabIndex) {
            btn.classList.add('text-white', 'border-blue-500');
            btn.classList.remove('text-gray-400', 'border-transparent');
        } else {
            btn.classList.remove('text-white', 'border-blue-500');
            btn.classList.add('text-gray-400', 'border-transparent');
        }
    });
}

// ── Export ───────────────────────────────────────────────────────────────────
function downloadReport(type) {
    if (!currentSessionId) { showToast('⚠️ Select a session from the sidebar first'); return; }
    if (type === 'csv')  window.open(`/api/scans/${currentSessionId}/csv`, '_blank');
    else if (type === 'json') window.open(`/api/scans/${currentSessionId}/json`, '_blank');
    else if (type === 'pdf') window.open(`/api/scans/${currentSessionId}/pdf`, '_blank');
    else showToast('📄 Export type not supported yet');
}

function exportAll() {
    if (!currentSessionId) { loadGlobalDashboard(); showToast('📊 Global dashboard refreshed'); return; }
    window.open(`/api/scans/${currentSessionId}/csv`, '_blank');
    setTimeout(() => window.open(`/api/scans/${currentSessionId}/json`, '_blank'), 500);
}

// ── Navigation ────────────────────────────────────────────────────────────────
function navigateTo(page) {
    if (page === 'scanner') window.location.href = '/';
    else window.location.href = '/' + page;
}

function refreshSessions() { fetchSessions(); }
function showSessionInfo() { if (currentSessionId) showToast(`📋 Session: ${currentSessionId}`); }

// ── Alert Settings Modal ──────────────────────────────────────────────────────

async function openAlertModal() {
    // Show modal
    document.getElementById('alert-modal-overlay').classList.remove('hidden');
    document.getElementById('alert-modal-box').classList.remove('hidden');

    // Load current settings from server
    try {
        const res  = await fetch('/api/alert-settings');
        const data = await res.json();

        document.getElementById('alert-email-input').value = data.alert_email || '';
        document.getElementById('alert-malicious-only-toggle').checked = !!data.alert_malicious_only;
        document.getElementById('alert-on-find-toggle').checked     = data.alert_on_find     !== false;
        document.getElementById('alert-on-complete-toggle').checked  = data.alert_on_complete !== false;

        // SMTP status banner
        const banner = document.getElementById('smtp-status-banner');
        if (data.smtp_configured) {
            banner.className = 'mx-8 mt-6 px-4 py-3 rounded-2xl text-xs font-medium bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center gap-2';
            banner.innerHTML = `<i class="fas fa-check-circle"></i> SMTP connected via <strong>${data.smtp_server}</strong> — ready to send alerts`;
            banner.classList.remove('hidden');
        } else {
            banner.className = 'mx-8 mt-6 px-4 py-3 rounded-2xl text-xs font-medium bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center gap-2';
            banner.innerHTML = `<i class="fas fa-exclamation-triangle"></i> SMTP not configured. Add <code class="bg-gray-800 px-1 rounded">MAIL_SERVER</code>, <code class="bg-gray-800 px-1 rounded">MAIL_USERNAME</code> and <code class="bg-gray-800 px-1 rounded">MAIL_PASSWORD</code> to your <strong>.env</strong> file.`;
            banner.classList.remove('hidden');
        }

        // Update bell dot indicator
        const dot = document.getElementById('alert-bell-dot');
        if (dot) dot.classList.toggle('hidden', !data.alert_email);
    } catch (e) {
        showToast('Failed to load alert settings', 'error');
    }
}

function closeAlertModal() {
    document.getElementById('alert-modal-overlay').classList.add('hidden');
    document.getElementById('alert-modal-box').classList.add('hidden');
}

async function saveAlertSettings() {
    const btn = document.getElementById('alert-save-btn');
    const email = document.getElementById('alert-email-input').value.trim();
    const maliciousOnly  = document.getElementById('alert-malicious-only-toggle').checked;
    const alertOnFind    = document.getElementById('alert-on-find-toggle').checked;
    const alertOnComplete = document.getElementById('alert-on-complete-toggle').checked;

    if (!alertOnFind && !alertOnComplete) {
        showToast('⚠️ Enable at least one alert mode', 'warn');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin text-xs"></i> Saving…';

    try {
        const res = await fetch('/api/alert-settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_email:          email,
                alert_malicious_only: maliciousOnly,
                alert_on_find:        alertOnFind,
                alert_on_complete:    alertOnComplete,
            })
        });
        const data = await res.json();
        if (data.error) {
            showToast('❌ ' + data.error, 'error');
        } else {
            closeAlertModal();
            showToast(
                email
                    ? `🔔 Alerts enabled → ${email}${maliciousOnly ? ' (Malicious only)' : ''}`
                    : '🔕 Email alerts disabled',
                'success'
            );
            // Update bell dot
            const dot = document.getElementById('alert-bell-dot');
            if (dot) dot.classList.toggle('hidden', !email);
        }
    } catch (e) {
        showToast('❌ Save failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-save text-xs"></i> Save Settings';
    }
}

async function sendTestEmail() {
    const testInput = document.getElementById('alert-test-email-input');
    const mainInput = document.getElementById('alert-email-input');
    const toEmail   = (testInput.value.trim()) || (mainInput.value.trim());
    const btn = document.getElementById('test-email-btn');

    if (!toEmail) {
        showToast('⚠️ Enter an email address first', 'warn');
        return;
    }
    // Basic RFC 5321 format check before hitting Gmail
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(toEmail);
    if (!emailOk) {
        showToast(`❌ "${toEmail}" is not a valid email address`, 'error');
        testInput.focus();
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin text-xs"></i> Sending…';

    try {
        const res = await fetch('/api/test-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to_email: toEmail })
        });
        const data = await res.json();
        if (data.error) {
            showToast('❌ ' + data.error, 'error');
        } else {
            showToast(`✅ Test email sent to ${toEmail}`, 'success');
        }
    } catch (e) {
        showToast('❌ Test failed: ' + e.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-paper-plane text-xs"></i> Send Test';
    }
}

// Close alert modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeAlertModal();
    }
});

// ── Continuous Monitoring (Scheduled Scans) ───────────────────────────────────

const INTERVAL_LABELS = { 1: 'Every Hour', 6: 'Every 6 Hours', 24: 'Daily', 168: 'Weekly' };

async function loadScheduledScans() {
    try {
        const res = await fetch('/api/scheduled-scans');
        if (!res.ok) return;
        const schedules = await res.json();
        renderSchedTable(schedules);
    } catch (e) { console.error('Failed to load monitors:', e); }
}

function renderSchedTable(schedules) {
    const tbody = document.getElementById('sched-table-body');
    if (!tbody) return;
    if (!schedules || schedules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-6 py-10 text-center text-gray-600 text-xs italic">No monitors configured yet.</td></tr>`;
        return;
    }
    tbody.innerHTML = schedules.map(s => {
        const intervalLabel = INTERVAL_LABELS[s.interval_hrs] || `${s.interval_hrs}h`;
        const lastRun = s.last_run_at ? new Date(s.last_run_at + 'Z').toLocaleString() : '—';
        const nextRun = s.next_run_at ? new Date(s.next_run_at + 'Z').toLocaleString() : '—';
        const statusBadge = s.enabled
            ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full bg-emerald-500/10 text-emerald-400 font-medium"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block"></span>Active</span>`
            : `<span class="px-2 py-0.5 text-xs rounded-full bg-gray-700 text-gray-400 font-medium">Paused</span>`;
        return `<tr class="hover:bg-gray-800/30 transition-colors">
            <td class="px-6 py-4 font-mono font-semibold text-white">${esc(s.domain)}</td>
            <td class="px-6 py-4 text-gray-400">${intervalLabel}</td>
            <td class="px-6 py-4 text-gray-500 text-xs">${lastRun}</td>
            <td class="px-6 py-4 text-gray-500 text-xs">${nextRun}</td>
            <td class="px-6 py-4 text-center">${statusBadge}</td>
            <td class="px-6 py-4 text-right">
                <div class="flex justify-end gap-2">
                    <button onclick="runSchedScanNow(${s.id}, this)" title="Scan immediately"
                        class="text-xs px-3 py-1.5 rounded-lg border border-blue-500/40 text-blue-400 hover:bg-blue-500/10 transition">
                        <i class="fas fa-play mr-1"></i>Scan Now
                    </button>
                    <button onclick="toggleScheduledScan(${s.id}, ${!s.enabled})"
                        class="text-xs px-3 py-1.5 rounded-lg border transition ${s.enabled ? 'border-amber-500/40 text-amber-400 hover:bg-amber-500/10' : 'border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10'}">
                        ${s.enabled ? 'Pause' : 'Enable'}
                    </button>
                    <button onclick="deleteScheduledScan(${s.id})"
                        class="text-xs px-3 py-1.5 rounded-lg border border-red-500/30 text-red-400 hover:bg-red-500/10 transition">
                        Delete
                    </button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

async function addScheduledScan() {
    const domainInput = document.getElementById('sched-domain-input');
    const intervalSelect = document.getElementById('sched-interval-select');
    const domain = domainInput.value.trim().toLowerCase();
    const interval_hrs = parseInt(intervalSelect.value);

    if (!domain) { showToast('❌ Please enter a domain to monitor'); return; }

    const btn = document.getElementById('sched-add-btn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';

    try {
        const res = await fetch('/api/scheduled-scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, interval_hrs })
        });
        const data = await res.json();
        if (data.error) { showToast('❌ ' + data.error); }
        else {
            showToast(`✅ Monitor added for ${domain}`);
            domainInput.value = '';
            loadScheduledScans();
        }
    } catch (e) {
        showToast('❌ Network error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-plus"></i> Add Monitor';
    }
}

async function toggleScheduledScan(id, enable) {
    try {
        await fetch(`/api/scheduled-scans/${id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enable })
        });
        loadScheduledScans();
    } catch (e) { showToast('❌ Failed to update monitor'); }
}

async function runSchedScanNow(id, btn) {
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i>Starting…';
    try {
        const res = await fetch(`/api/scheduled-scans/${id}/run-now`, { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
            showToast(`🚀 ${data.message} — check the sidebar for the new scan session`);
            // Refresh table after a moment so Last Run / Next Run updates
            setTimeout(loadScheduledScans, 3000);
        } else {
            showToast('❌ ' + (data.error || 'Failed to start scan'));
        }
    } catch (e) {
        showToast('❌ Network error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = original;
    }
}

async function deleteScheduledScan(id) {
    if (!confirm('Remove this monitoring schedule?')) return;
    try {
        await fetch(`/api/scheduled-scans/${id}`, { method: 'DELETE' });
        showToast('🗑️ Monitor removed');
        loadScheduledScans();
    } catch (e) { showToast('❌ Failed to delete monitor'); }
}

async function submitTakedown() {

    const domain = document.getElementById('modal-domain-name').textContent;
    if (!domain || !currentSessionId) return;

    const btn = document.getElementById('modal-takedown-btn');
    const originalText = btn.innerHTML;

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-1"></i> Sending...';

    try {
        const res = await fetch(`/api/scans/${currentSessionId}/domains/${encodeURIComponent(domain)}/notify-brand`, {
            method: 'POST'
        });
        const data = await res.json();

        if (data.error) {
            showToast('❌ Notification failed: ' + data.error);
            btn.disabled = false;
            btn.innerHTML = originalText;
        } else {
            showToast('✅ ' + data.message);
            // Lock in success state to prevent double-send
            btn.className = 'text-emerald-400 text-[11px] font-bold px-3 py-1.5 rounded-lg transition-all whitespace-nowrap border border-emerald-500/50 bg-emerald-600/20 cursor-not-allowed';
            btn.innerHTML = '<i class="fas fa-check-circle mr-1"></i>Alert Sent!';
        }
    } catch (e) {
        console.error(e);
        showToast('❌ Network error sending notification');
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.onload = function () {
    if (typeof tailwind !== 'undefined') tailwind.config = { darkMode: 'class' };

    if (!document.getElementById('sessions-list')) return;  // not a dashboard page

    console.log('%c🚀 PhishGuard Dashboard loaded', 'color:#10b981;font-size:14px;font-weight:bold');
    initSocket();
    fetchSessions();
    loadGlobalDashboard();
    loadScheduledScans();

    // Load bell dot state on page load
    fetch('/api/alert-settings').then(r => r.json()).then(data => {
        const dot = document.getElementById('alert-bell-dot');
        if (dot && data.alert_email) dot.classList.remove('hidden');
    }).catch(() => {});

    // Deep-link: /dashboard#<session-id>
    if (window.location.hash) {
        const sid = window.location.hash.substring(1);
        if (sid.length > 10) setTimeout(() => selectSession(sid), 400);
    }
};