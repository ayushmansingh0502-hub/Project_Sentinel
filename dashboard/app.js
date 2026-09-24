/*
 *  SwarmSentinel — D3 Force Graph Dashboard
 *  Clean enterprise visualization. No gimmicks.
 */

const WS_SCHEME = location.protocol === 'https:' ? 'wss' : 'ws';
const WS_URL = `${WS_SCHEME}://${location.host}/ws/live`;
const API = `${location.protocol}//${location.host}`;
const API_KEY_STORAGE_KEY = 'swarmsentinel_api_key';
let API_KEY = (localStorage.getItem(API_KEY_STORAGE_KEY) || '').trim();

let resolveApiKeyPromise = null;

function ensureApiKey() {
  if (API_KEY) return Promise.resolve(true);
  
  // Show modal to get API key
  return new Promise((resolve) => {
    resolveApiKeyPromise = resolve;
    showSettings(true);
  });
}

function showSettings(isFirstRun = false) {
  const modal = $('setupModal');
  const closeBtn = $('modalCloseBtn');
  if (modal) {
    modal.style.display = 'flex';
    $('modalApiKey').value = API_KEY;
    if (closeBtn) closeBtn.style.display = isFirstRun ? 'none' : 'inline-block';
    $('modalError').style.display = 'none';
  }
}

function hideSettings() {
  const modal = $('setupModal');
  if (modal) modal.style.display = 'none';
  if (resolveApiKeyPromise) {
    resolveApiKeyPromise(false);
    resolveApiKeyPromise = null;
  }
}

function saveSettings() {
  const entered = $('modalApiKey').value;
  if (!entered || !entered.trim()) {
    $('modalError').style.display = 'block';
    return;
  }
  API_KEY = entered.trim();
  localStorage.setItem(API_KEY_STORAGE_KEY, API_KEY);
  hideSettings();
  toast('API key configured', 'ok');
  connectWS();
  if (resolveApiKeyPromise) {
    resolveApiKeyPromise(true);
    resolveApiKeyPromise = null;
  }
}

function authHeaders(withJson = true) {
  const headers = {};
  if (withJson) headers['Content-Type'] = 'application/json';
  if (API_KEY) headers['x-api-key'] = API_KEY;
  return headers;
}

// Entity colors — muted, professional
const NODE_COLORS = {
  ip:     '#3B82F6',
  user:   '#8B5CF6',
  host:   '#06B6D4',
  domain: '#E5484D',
  honeypot: '#F59E0B',
  conversation: '#30A46C',
  unknown: '#6C6D70',
};

// State
let ws, reconnTimer;
let simulation, svg, container, linkLayer, nodeLayer, labelLayer;
let nodes = [], links = [];
let nodeById = new Map();
let incidents = [], feedCount = 0;
let selectedNode = null;
let searchQuery = '';
let traceMap = null;
let traceLayer = null;

const $ = id => document.getElementById(id);
const setText = (id, text) => { const el = $(id); if (el) el.textContent = text; };
const setHtml = (id, html) => { const el = $(id); if (el) el.innerHTML = html; };

// ═══════════════════════════════════════
//  D3 FORCE GRAPH
// ═══════════════════════════════════════

function initGraph() {
  const pane = $('graphPane');
  svg = d3.select('#graphSvg');

  // Defs
  const defs = svg.append('defs');

  // Legend
  const legEl = $('legendItems');
  if (legEl) {
    legEl.innerHTML = Object.entries(NODE_COLORS).map(([t, c]) => 
      `<div class="legend-item"><div class="legend-color" style="background:${c}"></div><span>${t}</span></div>`
    ).join('');
  }

  // Arrow markers for each color
  Object.entries(NODE_COLORS).forEach(([type, color]) => {
    defs.append('marker')
      .attr('id', `arrow-${type}`)
      .attr('viewBox', '0 -4 8 8')
      .attr('refX', 20).attr('refY', 0)
      .attr('markerWidth', 5).attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,-4L8,0L0,4Z')
      .attr('fill', color).attr('opacity', 0.5);
  });

  // Default arrow
  defs.append('marker')
    .attr('id', 'arrow-default')
    .attr('viewBox', '0 -4 8 8')
    .attr('refX', 20).attr('refY', 0)
    .attr('markerWidth', 5).attr('markerHeight', 5)
    .attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4Z')
    .attr('fill', '#3A3B40').attr('opacity', 0.5);

  container = svg.append('g');
  linkLayer = container.append('g');
  nodeLayer = container.append('g');
  labelLayer = container.append('g');

  // Zoom
  svg.call(d3.zoom()
    .scaleExtent([0.15, 4])
    .on('zoom', e => container.attr('transform', e.transform)));

  const w = pane.clientWidth, h = pane.clientHeight;

  simulation = d3.forceSimulation()
    .force('link', d3.forceLink().id(d => d.id).distance(110).strength(0.5))
    .force('charge', d3.forceManyBody().strength(-200).distanceMax(500))
    .force('center', d3.forceCenter(w / 2, h / 2).strength(0.05))
    .force('x', d3.forceX(w / 2).strength(0.03))
    .force('y', d3.forceY(h / 2).strength(0.03))
    .force('collision', d3.forceCollide().radius(d => radius(d) + 8))
    .on('tick', tick)
    .alphaDecay(0.015);
}

function radius(d) {
  const ph = d.pheromone || 0;
  return Math.max(5, Math.min(18, 5 + Math.sqrt(ph) * 1.8));
}

function edgeStroke(w) {
  if (w > 12) return '#E5484D';
  if (w > 6) return '#E5A336';
  if (w > 2) return '#3B82F6';
  return '#26272B';
}

function edgeWidth(w) {
  return Math.max(0.6, Math.min(3, 0.4 + Math.sqrt(w) * 0.5));
}

function edgeOpacity(w) {
  return Math.max(0.15, Math.min(0.7, 0.1 + w * 0.04));
}

function tick() {
  linkLayer.selectAll('line')
    .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);

  nodeLayer.selectAll('circle')
    .attr('cx', d => d.x).attr('cy', d => d.y);

  labelLayer.selectAll('text')
    .attr('x', d => d.x).attr('y', d => d.y + radius(d) + 12);
}

function renderGraph(data) {
  if (!data?.nodes) return;
  if (!simulation) initGraph();

  // Hide empty state
  const empty = $('graphEmpty');
  if (empty && data.nodes.length) empty.style.display = 'none';

  // Update metrics safely (handles cached html mismatch)
  const st = data.stats || {};
  setText('mNodes', st.node_count || data.nodes.length);
  setText('sNodes', st.node_count || data.nodes.length);
  setText('mEdges', st.edge_count || (data.edges || []).length);
  setText('sEdges', st.edge_count || (data.edges || []).length);
  setText('mPheromone', (st.total_pheromone || 0).toFixed(0));
  setText('sPheromone', (st.total_pheromone || 0).toFixed(0));

  // Sync nodes
  const pane = $('graphPane') || $('graphArea');
  if (!pane) return;
  const cx = pane.clientWidth / 2, cy = pane.clientHeight / 2;
  const incomingIds = new Set();

  for (const n of data.nodes) {
    incomingIds.add(n.id);
    if (nodeById.has(n.id)) {
      const existing = nodeById.get(n.id);
      existing.pheromone = n.pheromone || 0;
      existing.type = n.type || 'unknown';
      existing.metadata = n.metadata;
    } else {
      const obj = {
        id: n.id, type: n.type || 'unknown',
        pheromone: n.pheromone || 0, metadata: n.metadata,
        x: cx + (Math.random() - 0.5) * 300,
        y: cy + (Math.random() - 0.5) * 300,
      };
      nodeById.set(n.id, obj);
      nodes.push(obj);
    }
  }

  // Remove stale
  for (let i = nodes.length - 1; i >= 0; i--) {
    if (!incomingIds.has(nodes[i].id)) {
      nodeById.delete(nodes[i].id);
      nodes.splice(i, 1);
    }
  }

  // Build links
  links = [];
  for (const e of (data.edges || [])) {
    if (nodeById.has(e.source) && nodeById.has(e.target)) {
      links.push({
        source: e.source, target: e.target,
        weight: e.weight || 0, signal_types: e.signal_types || [],
      });
    }
  }

  // ── EDGES ──
  const edgeSel = linkLayer.selectAll('line').data(links, d => `${d.source.id||d.source}-${d.target.id||d.target}`);
  edgeSel.exit().remove();
  const edgeEnter = edgeSel.enter().append('line').attr('class', 'edge-line');
  edgeSel.merge(edgeEnter)
    .attr('stroke', d => edgeStroke(d.weight))
    .attr('stroke-width', d => edgeWidth(d.weight))
    .attr('stroke-opacity', d => edgeOpacity(d.weight))
    .attr('marker-end', d => {
      const targetNode = nodeById.get(d.target.id || d.target);
      const type = targetNode ? targetNode.type : 'default';
      return `url(#arrow-${NODE_COLORS[type] ? type : 'default'})`;
    });

  // ── NODES ──
  const nodeSel = nodeLayer.selectAll('circle').data(nodes, d => d.id);
  nodeSel.exit().remove();
  const nodeEnter = nodeSel.enter().append('circle')
    .attr('class', 'node-circle')
    .call(d3.drag()
    .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }))
    .on('mouseover', (e, d) => showTip(e, d))
    .on('mouseout', () => hideTip())
    .on('click', (e, d) => { e.stopPropagation(); showDetailPanel(d); })
    .on('contextmenu', (e, d) => { e.preventDefault(); showContextMenu(e, d); });

  nodeSel.merge(nodeEnter)
    .attr('r', d => radius(d))
    .attr('fill', d => NODE_COLORS[d.type] || NODE_COLORS.unknown)
    .attr('stroke', d => {
      const c = d3.color(NODE_COLORS[d.type] || NODE_COLORS.unknown);
      return c ? c.brighter(0.8).toString() : '#6C6D70';
    })
    .attr('stroke-width', d => d.pheromone > 15 ? 2 : 1)
    .attr('stroke-opacity', 0.4);

  // ── LABELS ──
  const lblData = nodes.filter(d => d.pheromone > 2);
  const lblSel = labelLayer.selectAll('text').data(lblData, d => d.id);
  lblSel.exit().remove();
  const lblEnter = lblSel.enter().append('text').attr('class', 'node-label');
  lblSel.merge(lblEnter)
    .text(d => {
      const raw = d.id.includes(':') ? d.id.split(':').slice(1).join(':') : d.id;
      return raw.length > 22 ? raw.substring(0, 20) + '..' : raw;
    });

  // Restart sim
  simulation.nodes(nodes);
  simulation.force('link').links(links);
  simulation.alpha(0.25).restart();
}

// Tooltip
function showTip(event, d) {
  const t = $('tooltip');
  const name = d.id.includes(':') ? d.id.split(':').slice(1).join(':') : d.id;
  t.innerHTML = `<span class="t-name">${esc(name)}</span><br>`
    + `<span class="t-dim">Type</span> <span class="t-val">${esc(d.type)}</span><br>`
    + `<span class="t-dim">Pheromone</span> <span class="t-val">${(d.pheromone||0).toFixed(1)}</span>`
    + (d.metadata && Object.keys(d.metadata).length ? `<br><span class="t-dim">Meta</span> <span class="t-val">${JSON.stringify(d.metadata)}</span>` : '');
  t.style.display = 'block';

  // Position relative to graph pane
  const pane = $('graphPane') || $('graphArea');
  if (pane) {
    const rect = pane.getBoundingClientRect();
    t.style.left = (event.clientX - rect.left + 12) + 'px';
    t.style.top = (event.clientY - rect.top - 10) + 'px';
  }
}

function hideTip() { 
  const t = $('tooltip');
  if (t) t.style.display = 'none'; 
}

// ═══════════════════════════════════════
//  TABS
// ═══════════════════════════════════════

function switchTab(tab) {
  document.querySelectorAll('.panel-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  $('panelIncidents').hidden = tab !== 'incidents';
  $('panelFeed').hidden = tab !== 'feed';
  $('panelPredictions').hidden = tab !== 'predictions';
  $('panelTrace').hidden = tab !== 'trace';
  if (tab === 'trace' && traceMap) setTimeout(() => traceMap.invalidateSize(), 0);
}

function initTraceMap() {
  const el = $('traceMap');
  if (!el || typeof L === 'undefined') return;
  traceMap = L.map(el, { zoomControl: false, attributionControl: true }).setView([20, 0], 2);
  L.control.zoom({ position: 'bottomright' }).addTo(traceMap);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18,
    attribution: '&copy; OpenStreetMap contributors',
  }).addTo(traceMap);
  traceLayer = L.layerGroup().addTo(traceMap);
}

function renderEmailTrace(data) {
  const rawHops = data?.hops || data?.relay_hops || data?.header_analysis?.relay_hops || [];
  const origin = data?.origin_trace || data?.origin || {};
  const header = data?.header_analysis || {};
  const auth = header.authentication || data?.authentication || {};
  const domain = data?.domain_intel || {};
  const spoof = data?.brand_spoof || {};
  const hops = rawHops.filter(h => Number.isFinite(Number(h.lat ?? h.latitude)) && Number.isFinite(Number(h.lon ?? h.longitude)));
  if (!hops.length && Number.isFinite(Number(origin.latitude)) && Number.isFinite(Number(origin.longitude))) {
    hops.push({ ip: origin.ip, city: origin.city, country: origin.country, latitude: origin.latitude, longitude: origin.longitude });
  }
  setText('traceBadge', rawHops.length || (origin.ip ? 1 : 0));
  setText('traceSummary', origin.ip ? `Probable origin: ${origin.ip}` : (rawHops.length ? `${rawHops.length} relay hops` : 'No geolocation data available'));
  const evidence = $('traceEvidence');
  if (evidence) {
    const authRows = ['spf', 'dkim', 'dmarc'].map(name => `<span class="evidence-chip ${auth[name] === 'pass' ? 'good' : auth[name] ? 'bad' : ''}">${name.toUpperCase()}: ${esc(auth[name] || 'unavailable')}</span>`).join('');
    const signals = [...(header.anomalies || []), ...(domain.reputation_signals || [])];
    if (spoof.suspected) signals.push(`brand spoof: ${spoof.matched_brand || 'suspected'}`);
    evidence.innerHTML = `${authRows}<div class="evidence-signals">${signals.length ? signals.map(signal => `<span class="evidence-signal">${esc(signal)}</span>`).join('') : 'No additional forensic signals'}</div>`;
  }
  const path = $('tracePath');
  if (path) {
    path.innerHTML = rawHops.map((hop, index) => {
      const label = hop.ip || hop.host || hop.from_host || `Hop ${index + 1}`;
      const location = [hop.city, hop.country].filter(Boolean).join(', ') || 'Location unavailable';
      return `<div class="trace-hop"><span class="trace-index">${index + 1}</span><div><div class="trace-host">${esc(label)}</div><div class="trace-location">${esc(location)}</div></div></div>`;
    }).join('') || '<div class="empty-msg">No relay hops available</div>';
  }
  if (!traceMap || !traceLayer) return;
  traceLayer.clearLayers();
  if (!hops.length) return;
  const points = hops.map(h => [Number(h.lat ?? h.latitude), Number(h.lon ?? h.longitude)]);
  L.polyline(points, { color: '#6E7BF5', weight: 3, opacity: 0.85 }).addTo(traceLayer);
  hops.forEach((hop, index) => {
    const point = [Number(hop.lat ?? hop.latitude), Number(hop.lon ?? hop.longitude)];
    L.circleMarker(point, { radius: 6, color: index === hops.length - 1 ? '#E5484D' : '#30A46C', fillOpacity: 0.9 })
      .bindTooltip(`${index + 1}. ${hop.ip || hop.host || 'relay'}`)
      .addTo(traceLayer);
  });
  traceMap.fitBounds(points, { padding: [20, 20], maxZoom: 8 });
}

async function analyzeEmailFromDashboard(event) {
  event.preventDefault();
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  const error = $('traceError');
  if (error) error.textContent = '';
  const body = {
    from_email: $('traceFromEmail').value.trim(),
    from_name: $('traceFromName').value.trim() || null,
    message_text: $('traceMessage').value.trim(),
  };
  const headers = $('traceHeaders').value.trim();
  if (headers) body.raw_headers = headers;
  try {
    const response = await fetch(`${API}/analyze-email`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || `HTTP ${response.status}`);
    renderEmailTrace(result);
    switchTab('trace');
    toast(`Email analyzed: ${result.risk?.risk_level || 'unknown'} risk`, result.is_scam ? 'err' : 'ok');
  } catch (err) {
    if (error) error.textContent = err.message;
    toast('Email analysis failed', 'err');
  }
}

// ═══════════════════════════════════════
//  WEBSOCKET
// ═══════════════════════════════════════

async function connectWS() {
  if (!API_KEY) return;
  if (ws && ws.readyState === WebSocket.OPEN) return;
  
  try {
    const res = await fetch(`${API}/ws-ticket`, {
      method: 'POST',
      headers: authHeaders()
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        toast('Invalid API Key. Please check settings.', 'err');
        showSettings();
      }
      return;
    }
    const { ticket } = await res.json();
    ws = new WebSocket(`${WS_URL}?ticket=${ticket}`);
    ws.onopen = () => {
      setConn(true);
      toast('Connected', 'ok');
      if (reconnTimer) { clearTimeout(reconnTimer); reconnTimer = null; }
    };
    ws.onmessage = e => { try { route(JSON.parse(e.data)); } catch(err) { console.error(err); } };
    ws.onclose = () => { setConn(false); if (API_KEY) schedReconn(); };
    ws.onerror = () => setConn(false);
  } catch (err) {
    console.error('WS auth error:', err);
    schedReconn();
  }
}

function schedReconn() { if (reconnTimer) return; reconnTimer = setTimeout(() => { reconnTimer = null; connectWS(); }, 3000); }

function setConn(ok) {
  const dot = $('connDot') || $('connStatus');
  if (dot) dot.classList.toggle('live', ok);
  setText('connLabel', ok ? 'Connected' : 'Offline');
}

function route(msg) {
  const { type, data, timestamp } = msg;
  const messageType = type || msg.msg_type;
  switch (messageType) {
    case 'auth_ok': setConn(true); toast('Connected', 'ok'); break;
    case 'init':
      if (data.graph) renderGraph(data.graph);
      if (data.incidents) { incidents = data.incidents; renderInc(); }
      if (data.swarm) updateSwarm(data.swarm);
      $('simLabel').textContent = data.simulation_running ? 'Running' : 'Idle';
      break;
    case 'graph_update': renderGraph(data); applySearchFilter(); break;
    case 'telemetry': onTelemetry(data, timestamp); break;
    case 'incident': onIncident(data, timestamp); break;
    case 'ant_activity': onAnt(data, timestamp); break;
    case 'swarm_status': updateSwarm(data); break;
    case 'simulation_start': onSimStart(data); break;
    case 'simulation_end': onSimEnd(data); break;
    case 'containment_action': onContainment(data, timestamp); break;
    case 'email_trace': renderEmailTrace(data); switchTab('trace'); break;
  }
}

// ═══════════════════════════════════════
//  EVENT HANDLERS
// ═══════════════════════════════════════

function onTelemetry(data, ts) {
  const ev = data.event || {};
  const id = `${ev.entity_type}:${ev.entity_id}`;
  const score = ev.enriched_score || 0;
  const cls = score >= 70 ? 'threat' : score >= 40 ? 'swarm' : 'event';
  addFeed(cls, id, `score ${score.toFixed(0)}`, ts);

  if (data.graph_stats) {
    setText('mNodes', data.graph_stats.node_count || 0);
    setText('sNodes', data.graph_stats.node_count || 0);
    setText('mEdges', data.graph_stats.edge_count || 0);
    setText('sEdges', data.graph_stats.edge_count || 0);
    setText('mPheromone', (data.graph_stats.total_pheromone || 0).toFixed(0));
    setText('sPheromone', (data.graph_stats.total_pheromone || 0).toFixed(0));
  }
  if (data.progress) {
    setText('simLabel', data.progress);
    const lbl = $('simLabel');
    if (lbl) lbl.className = 'ctrl-label active';
    const m = data.progress.match(/(\d+)\/(\d+)/);
    const pb = $('progressBar');
    if (m && pb) pb.style.width = (parseInt(m[1]) / parseInt(m[2]) * 100) + '%';
  }
}

function onIncident(data, ts) {
  incidents.unshift(data);
  renderInc();
  setText('mIncidents', incidents.length);
  setText('sIncidents', incidents.length);
  const ents = (data.entities || []).map(e => `${e.type}:${e.id}`).join(', ');
  addFeed('threat', `INC-${data.id}  score:${(data.score || 0).toFixed(0)}`, ents, ts);
  toast(`Incident #${data.id} — score ${(data.score || 0).toFixed(0)}`, 'err');
}

function onAnt(data, ts) {
  addFeed('swarm', data.ant_id || 'Swarm', data.event || '', ts);
}

function updateSwarm(s) {
  const n = (s.scout_count || 0) + (s.soldier_count || 0);
  setText('mAnts', n);
  setText('sAnts', n);
  const onBtn = $('btnSwarmOn');
  const offBtn = $('btnSwarmOff');
  if (onBtn) onBtn.disabled = s.is_running;
  if (offBtn) offBtn.disabled = !s.is_running;
}

function onSimStart(data) {
  setText('simLabel', data.scenario);
  const lbl = $('simLabel');
  if (lbl) lbl.className = 'ctrl-label active';
  
  const bRun = $('btnRun'), bAdd = $('btnAdd'), bStop = $('btnStop');
  if (bRun) bRun.disabled = true; 
  if (bAdd) bAdd.disabled = true; 
  if (bStop) bStop.disabled = false;
  
  const pb = $('progressBar');
  if (pb) pb.style.width = '0%';
  
  addFeed('system', 'Simulation started', `${data.scenario} — ${data.event_count} events`, Date.now() / 1000);
}

function onSimEnd(data) {
  setText('simLabel', 'Idle');
  const lbl = $('simLabel');
  if (lbl) lbl.className = 'ctrl-label';
  
  const bRun = $('btnRun'), bAdd = $('btnAdd'), bStop = $('btnStop');
  if (bRun) bRun.disabled = false; 
  if (bAdd) bAdd.disabled = false; 
  if (bStop) bStop.disabled = true;
  
  const pb = $('progressBar');
  if (pb) pb.style.width = '100%';
  setTimeout(() => { if (pb) pb.style.width = '0%'; }, 1200);
  
  addFeed('system', 'Simulation complete', data.scenario, Date.now() / 1000);
  toast(`${data.scenario} complete`, 'ok');
}

// ═══════════════════════════════════════
//  FEED + INCIDENTS
// ═══════════════════════════════════════

function addFeed(cls, title, desc, ts) {
  feedCount++;
  setText('feedBadge', feedCount);
  setText('feedCount', feedCount);
  const el = $('feedList');
  if (!el) return;
  const t = ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
  const row = document.createElement('div');
  row.className = 'feed-item';
  row.innerHTML = `<span class="feed-dot ${cls}"></span><div class="feed-body"><div class="feed-title">${esc(title)}</div><div class="feed-desc">${esc(desc)}</div></div><span class="feed-ts">${t}</span>`;
  el.insertBefore(row, el.firstChild);
  while (el.children.length > 100) el.removeChild(el.lastChild);
}

function renderInc() {
  const el = $('incList');
  setText('incBadge', incidents.length);
  setText('incCount', incidents.length);
  const emptyEl = $('incEmpty');
  if (emptyEl) emptyEl.style.display = incidents.length ? 'none' : 'block';

  if (!el) return;
  el.innerHTML = incidents.slice(0, 25).map(inc => {
    const s = inc.score || 0;
    const sev = s >= 80 ? 'crit' : s >= 60 ? 'high' : 'med';
    const entityIds = (inc.entities || []).map(e => `${e.type}:${e.id}`);
    const ents = entityIds.join(', ');
    const tags = (inc.mitre || []).map(t => `<span class="tag">${esc(t)}</span>`).join('');
    return `<div class="inc-item js-highlight-entities" data-highlight-entities="${esc(JSON.stringify(entityIds))}" style="cursor:pointer"><div class="inc-top"><span class="inc-id">INC-${esc(inc.id)}</span><span class="inc-score ${sev}">${s.toFixed(0)}</span></div><div class="inc-entities">${esc(ents)}</div>${tags ? `<div class="inc-tags">${tags}</div>` : ''}</div>`;
  }).join('');
  bindHighlightHandlers(el);
}

function bindHighlightHandlers(container) {
  container.querySelectorAll('[data-highlight-entities]').forEach(element => {
    element.addEventListener('click', () => {
      try {
        highlightEntities(JSON.parse(element.dataset.highlightEntities || '[]'));
      } catch (_) {
        // Ignore malformed data attributes rather than executing page content.
      }
    });
  });
}

// ═══════════════════════════════════════
//  API
// ═══════════════════════════════════════

async function resetAndRun() {
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  try { await fetch(`${API}/swarm/reset`, { method: 'POST', headers: authHeaders() }); } catch (e) {}
  nodes = []; links = []; nodeById.clear();
  incidents = []; feedCount = 0;
  renderInc(); setHtml('feedList', ''); setText('feedBadge', '0'); setText('feedCount', '0');
  setText('mNodes', '0'); setText('sNodes', '0'); 
  setText('mEdges', '0'); setText('sEdges', '0');
  setText('mPheromone', '0'); setText('sPheromone', '0'); 
  setText('mIncidents', '0'); setText('sIncidents', '0');
  if (simulation && linkLayer && nodeLayer && labelLayer) { 
    linkLayer.selectAll('*').remove(); 
    nodeLayer.selectAll('*').remove(); 
    labelLayer.selectAll('*').remove(); 
  }
  const e = $('graphEmpty') || $('watermark'); 
  if (e) e.style.display = 'flex';
  await runScenario();
}

async function runScenario() {
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  const sel = $('scenarioSelect');
  const sc = sel ? sel.value : 'apt_killchain';
  try {
    const r = await fetch(`${API}/swarm/simulate`, { method: 'POST', headers: authHeaders(), body: JSON.stringify({ action: 'scenario', scenario: sc, events_per_second: 2.5 }) });
    if (!r.ok) {
      if (r.status === 401 || r.status === 403) {
        toast('Invalid API Key. Please check settings.', 'err');
        showSettings();
        return;
      }
      throw new Error(`HTTP error ${r.status}`);
    }
    const d = await r.json();
    if (d.status === 'already_running') toast('Simulation already running', 'err');
  } catch (e) { toast('Failed: ' + e.message, 'err'); }
}

async function stopSim() {
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  try { await fetch(`${API}/swarm/simulate`, { method: 'POST', headers: authHeaders(), body: JSON.stringify({ action: 'stop' }) }); } catch (e) {}
  setText('simLabel', 'Stopping');
}

async function swarmStart() {
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  try {
    const r = await fetch(`${API}/swarm/start`, { method: 'POST', headers: authHeaders() });
    const d = await r.json();
    if (d.status === 'started') { 
      toast('Swarm active', 'ok'); 
      const on = $('btnSwarmOn'), off = $('btnSwarmOff');
      if (on) on.disabled = true; 
      if (off) off.disabled = false; 
    }
  } catch (e) { toast('Failed', 'err'); }
}

async function swarmStop() {
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  try { 
    await fetch(`${API}/swarm/stop`, { method: 'POST', headers: authHeaders() }); 
    toast('Swarm stopped', 'ok'); 
    const on = $('btnSwarmOn'), off = $('btnSwarmOff');
    if (on) on.disabled = false; 
    if (off) off.disabled = true; 
  }
  catch (e) { toast('Failed', 'err'); }
}

// ═══════════════════════════════════════
//  UTILS
// ═══════════════════════════════════════

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function toast(msg, cls) {
  const c = $('toasts') || document.body;
  const el = document.createElement('div');
  el.className = `toast ${cls || ''}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 3500);
}

// ═══════════════════════════════════════
//  INTERACTIVITY & DASHBOARD UX
// ═══════════════════════════════════════

function onContainment(data, ts) {
  toast(`Containment: ${data.action ? data.action.action : 'Action'} on ${data.action ? data.action.entity_id : 'entity'}`, 'ok');
}

function showDetailPanel(node) {
  selectedNode = node;
  const p = $('detailPanel');
  if (!p) return;
  const rawId = node.id.includes(':') ? node.id.split(':').slice(1).join(':') : node.id;
  setText('detailTitle', rawId);
  let html = `<div class="prop-row"><span class="prop-lbl">Type</span><span class="prop-val">${esc(node.type)}</span></div>`;
  html += `<div class="prop-row"><span class="prop-lbl">Pheromone</span><span class="prop-val">${(node.pheromone||0).toFixed(1)}</span></div>`;
  if (node.metadata && Object.keys(node.metadata).length > 0) {
    html += `<div class="prop-lbl" style="margin-top:12px">Metadata</div><div class="meta-block">${esc(JSON.stringify(node.metadata, null, 2))}</div>`;
  }
  
  // Find connected edges
  const connected = links.filter(l => (l.source.id||l.source) === node.id || (l.target.id||l.target) === node.id);
  html += `<div class="prop-lbl" style="margin-top:12px">Connected Edges (${connected.length})</div>`;
  connected.slice(0, 20).forEach(l => {
    const isSrc = (l.source.id||l.source) === node.id;
    const otherId = isSrc ? (l.target.id||l.target) : (l.source.id||l.source);
    html += `<div class="feed-item js-highlight-entities" data-highlight-entities="${esc(JSON.stringify([otherId]))}" style="margin-top:4px;cursor:pointer"><div class="feed-body"><div class="feed-title">${esc(otherId)}</div><div class="feed-desc">Weight: ${(l.weight||0).toFixed(1)} | ${esc((l.signal_types||[]).join(', '))}</div></div></div>`;
  });

  setHtml('detailBody', html);
  bindHighlightHandlers($('detailBody'));
  p.classList.add('open');
}

function hideDetailPanel() {
  const p = $('detailPanel');
  if (p) p.classList.remove('open');
  selectedNode = null;
  clearHighlight();
}

function showContextMenu(e, node) {
  const m = $('ctxMenu');
  if (!m) return;
  m.style.left = e.clientX + 'px';
  m.style.top = e.clientY + 'px';
  m.style.display = 'block';
  m.dataset.nodeId = node.id;
  m.dataset.nodeType = node.type;
}

function hideContextMenu() {
  const m = $('ctxMenu');
  if (m) m.style.display = 'none';
}

function highlightEntities(ids) {
  const idSet = new Set(ids);
  if (nodeLayer) nodeLayer.selectAll('circle').classed('dimmed', d => !idSet.has(d.id)).classed('highlight', d => idSet.has(d.id));
  if (linkLayer) linkLayer.selectAll('line').classed('dimmed', d => !idSet.has(d.source.id||d.source) && !idSet.has(d.target.id||d.target));
  
  // Center on first ID if possible
  if (ids.length > 0 && nodeById.has(ids[0]) && simulation) {
    const n = nodeById.get(ids[0]);
    const p = $('graphPane') || $('graphArea');
    if (p) {
      simulation.force('center', d3.forceCenter(p.clientWidth/2 - n.x*0.5, p.clientHeight/2 - n.y*0.5));
      simulation.alpha(0.3).restart();
      setTimeout(() => {
        simulation.force('center', d3.forceCenter(p.clientWidth/2, p.clientHeight/2));
      }, 1000);
    }
  }
}

function clearHighlight() {
  if (nodeLayer) nodeLayer.selectAll('circle').classed('dimmed', false).classed('highlight', false);
  if (linkLayer) linkLayer.selectAll('line').classed('dimmed', false);
  applySearchFilter(); // Restore search if active
}

function applySearchFilter() {
  if (!searchQuery) {
    if (nodeLayer) nodeLayer.selectAll('circle').classed('dimmed', false).classed('highlight', false);
    if (linkLayer) linkLayer.selectAll('line').classed('dimmed', false);
    return;
  }
  const q = searchQuery.toLowerCase();
  const idSet = new Set();
  nodes.forEach(n => {
    if (n.id.toLowerCase().includes(q)) idSet.add(n.id);
  });
  if (nodeLayer) nodeLayer.selectAll('circle').classed('dimmed', d => !idSet.has(d.id)).classed('highlight', d => idSet.has(d.id));
  if (linkLayer) linkLayer.selectAll('line').classed('dimmed', d => !idSet.has(d.source.id||d.source) && !idSet.has(d.target.id||d.target));
}

async function execContainment(action, entityId, entityType, reason) {
  const hasKey = await ensureApiKey();
  if (!hasKey) return;
  toast(`Requesting ${action}...`, 'ok');
  try {
    const r = await fetch(`${API}/containment/action`, { 
      method: 'POST', headers: authHeaders(), 
      body: JSON.stringify({ action, entity_id: entityId, entity_type: entityType, reason }) 
    });
    if (!r.ok) toast('Containment failed', 'err');
  } catch (e) { toast('Containment failed', 'err'); }
}

async function fetchPredictions() {
  if (!API_KEY) return;
  try {
    const r = await fetch(`${API}/swarm/graph`, { headers: authHeaders(false) });
    const d = await r.json();
    if (d.status === 'ok' && d.predictions && d.predictions.length > 0) {
      setText('predBadge', d.predictions.length);
      const el = $('predList');
      if (el) {
        el.innerHTML = d.predictions.map(p => 
          `<div class="inc-item js-highlight-entities" data-highlight-entities="${esc(JSON.stringify([p.entity_id]))}" style="cursor:pointer">
            <div class="inc-top"><span class="inc-id">${esc(p.entity_id.split(':').slice(1).join(':'))}</span><span class="inc-score crit">${p.risk_score.toFixed(1)}</span></div>
            <div class="inc-entities" style="font-size:10px">${esc(p.reason)}</div>
          </div>`
        ).join('');
        bindHighlightHandlers(el);
        $('predEmpty').style.display = 'none';
      }
    }
  } catch (e) {}
}

// ── Init ──
document.addEventListener('DOMContentLoaded', () => {
  initGraph();
  initTraceMap();
  if (API_KEY) connectWS();
  setInterval(() => { if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'request_status' })); }, 8000);
  window.addEventListener('resize', () => {
    if (!simulation) return;
    const p = $('graphPane') || $('graphArea');
    if (!p) return;
    simulation.force('center', d3.forceCenter(p.clientWidth / 2, p.clientHeight / 2));
    simulation.force('x', d3.forceX(p.clientWidth / 2).strength(0.03));
    simulation.force('y', d3.forceY(p.clientHeight / 2).strength(0.03));
    simulation.alpha(0.1).restart();
  });

  // Expose UI functions globally
  window.showSettings = showSettings;
  window.hideSettings = hideSettings;
  window.saveSettings = saveSettings;
  window.resetAndRun = resetAndRun;
  window.runScenario = runScenario;
  window.stopSim = stopSim;
  window.swarmStart = swarmStart;
  window.swarmStop = swarmStop;
  window.switchTab = switchTab;
  window.highlightEntities = highlightEntities;
  window.renderEmailTrace = renderEmailTrace;
  const traceForm = $('emailTraceForm');
  if (traceForm) traceForm.addEventListener('submit', analyzeEmailFromDashboard);

  // Check API Key on load
  if (!API_KEY) {
    setTimeout(() => showSettings(true), 500);
  }

  // DOM Events
  document.addEventListener('click', () => { hideContextMenu(); if (!selectedNode) clearHighlight(); });
  
  const searchInput = $('searchInput');
  if (searchInput) {
    searchInput.addEventListener('input', e => { searchQuery = e.target.value; applySearchFilter(); });
    $('searchClear')?.addEventListener('click', () => { searchInput.value = ''; searchQuery = ''; applySearchFilter(); });
  }

  $('detailClose')?.addEventListener('click', hideDetailPanel);
  
  $('btnInvestigate')?.addEventListener('click', () => { if (selectedNode) highlightEntities([selectedNode.id]); });
  $('btnBlock')?.addEventListener('click', () => { if (selectedNode) execContainment('block_ip', selectedNode.id.split(':').slice(1).join(':'), selectedNode.type, 'Dashboard Block'); });
  $('btnIsolate')?.addEventListener('click', () => { if (selectedNode) execContainment('isolate_host', selectedNode.id.split(':').slice(1).join(':'), selectedNode.type, 'Dashboard Isolate'); });
  $('btnEscalate')?.addEventListener('click', () => { if (selectedNode) execContainment('escalate', selectedNode.id.split(':').slice(1).join(':'), selectedNode.type, 'Dashboard Escalate'); });

  $('ctxMenu')?.addEventListener('click', e => {
    const item = e.target.closest('.ctx-item');
    if (!item) return;
    const m = $('ctxMenu');
    const nid = m.dataset.nodeId;
    const ntype = m.dataset.nodeType;
    const rawId = nid.includes(':') ? nid.split(':').slice(1).join(':') : nid;
    
    switch(item.dataset.action) {
      case 'inspect': if (nodeById.has(nid)) showDetailPanel(nodeById.get(nid)); break;
      case 'block': execContainment('block_ip', rawId, ntype, 'Context Menu'); break;
      case 'isolate': execContainment('isolate_host', rawId, ntype, 'Context Menu'); break;
      case 'escalate': execContainment('escalate', rawId, ntype, 'Context Menu'); break;
      case 'copy': navigator.clipboard.writeText(rawId); toast('Copied', 'ok'); break;
    }
  });

  document.addEventListener('keydown', e => {
    if (e.target.tagName === 'INPUT') {
      if (e.key === 'Escape') { e.target.blur(); hideDetailPanel(); }
      return;
    }
    if (e.key === 'r' || e.key === 'R') resetAndRun();
    if (e.key === 's' || e.key === 'S') stopSim();
    if (e.key === '/') { e.preventDefault(); searchInput?.focus(); }
    if (e.key === 'Escape') hideDetailPanel();
  });

  setInterval(fetchPredictions, 10000);
});
