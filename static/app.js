(() => {
  'use strict';

  let apiToken = '';
  let modelInfo = {};
  let latestEvents = [];
  let latestFindings = [];
  let eventFilter = 'all';
  let timer = null;
  let toastTimer = null;
  let lastAnalytics = null;
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const connectScreen = $('#connect-screen');
  const appShell = $('#app-shell');
  const dialog = $('#event-dialog');

  const textNode = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = String(value);
    return node;
  };
  const safeNum = value => Number.isFinite(Number(value)) ? Number(value) : 0;
  const fmt = value => new Intl.NumberFormat().format(safeNum(value));
  const pct = value => `${(safeNum(value) * 100).toFixed(1)}%`;
  const pretty = value => String(value || 'unknown').replaceAll('-', ' ').replaceAll('_', ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
  const shortTime = value => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined,
      {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}).format(date);
  };
  function setBarWidth(element, fraction) {
    const step = Math.max(1, Math.min(20, Math.round(Math.max(0, Math.min(1, fraction)) * 20)));
    element.classList.add(`bar-w-${step}`);
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${apiToken}`);
    if (options.body) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {...options, headers, cache:'no-store'});
    let body = {};
    try { body = await response.json(); } catch (_) { /* show a short fallback below */ }
    if (response.status === 401) throw new Error('The token was rejected. Disconnect and enter the current API token.');
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  }

  function showToast(message) {
    const toast = $('#toast');
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 2800);
  }

  function setConnection(ready, message = ready ? 'Service online' : 'Service unavailable') {
    const cls = ready ? 'status-dot status-ok' : 'status-dot status-bad';
    $('#sidebar-dot').className = cls;
    $('#top-status-dot').className = cls;
    $('#integration-dot').className = cls;
    $('#sidebar-status').textContent = ready ? 'Service online' : 'Disconnected';
    $('#top-status').textContent = ready ? 'Live service' : 'Reconnect';
    $('#integration-state-text').textContent = ready ? 'Scoring service ready' : message;
  }

  function setTheme(theme) {
    const resolved = theme === 'system'
      ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
    document.body.dataset.theme = resolved;
    $('#theme-select').value = theme;
    localStorage.setItem('cloudids-theme', theme);
    drawChart(lastAnalytics?.series || []);
  }

  async function connect(token) {
    apiToken = token.trim();
    const error = $('#connect-error');
    error.textContent = '';
    try {
      const [schema, meta] = await Promise.all([api('/v1/schema'), api('/v1/model')]);
      modelInfo = {...meta, schema};
      connectScreen.hidden = true;
      appShell.hidden = false;
      $('#schema-count').textContent = fmt(schema.feature_count);
      $('#model-version').textContent = `MODEL ${meta.model_version || '—'}`;
      $('#footer-model').textContent = `· ${meta.model_version || '—'}`;
      setConnection(true);
      renderModels(meta);
      await refreshAll();
      startPolling();
      navigate(location.hash.slice(1) || 'overview');
    } catch (err) {
      apiToken = '';
      error.textContent = err.message;
      setConnection(false, err.message);
    }
  }

  function disconnect() {
    apiToken = '';
    if (timer) clearInterval(timer);
    timer = null;
    $('#api-token').value = '';
    appShell.hidden = true;
    connectScreen.hidden = false;
    $('#connect-error').textContent = '';
    setConnection(false, 'Connect with a local API token');
  }

  function startPolling() {
    if (timer) clearInterval(timer);
    const seconds = Number($('#poll-select').value || localStorage.getItem('cloudids-poll') || 10);
    timer = setInterval(() => refreshAll().catch(handleApiError), seconds * 1000);
  }

  async function refreshAll() {
    if (!apiToken) return;
    const hours = Number($('#range-select').value || 24);
    const [analytics, eventData, findingData] = await Promise.all([
      api(`/v1/analytics?hours=${hours}`),
      api('/v1/events?limit=100&alert=all'),
      api('/v1/provider-findings?limit=100')
    ]);
    lastAnalytics = analytics;
    latestEvents = eventData.events || [];
    latestFindings = findingData.findings || [];
    renderAnalytics(analytics);
    renderEvents();
    renderFindings();
    renderRecent();
    renderProviderSummary(analytics.provider_findings || {});
    $('#last-updated').textContent = `Synced ${new Intl.DateTimeFormat(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date())}`;
    setConnection(true);
  }

  function handleApiError(error) {
    setConnection(false, error.message);
    if (error.message.includes('token was rejected')) disconnect();
    else showToast(error.message || 'Could not refresh data');
  }

  function renderAnalytics(data) {
    $('#stat-events').textContent = fmt(data.events);
    $('#stat-alerts').textContent = fmt(data.alerts);
    const totalProviderFindings = Object.values(data.provider_findings || {}).reduce((sum, value) => sum + safeNum(value), 0);
    $('#stat-findings').textContent = fmt(totalProviderFindings);
    $('#stat-score').textContent = safeNum(data.mean_score).toFixed(3);
    $('#nav-alert-count').textContent = fmt(data.alerts);
    $('#chart-period').textContent = `${data.hours}H`;
    drawChart(data.series || []);
    renderBreakdown(data.attack_classes || []);
  }

  function drawChart(series) {
    const canvas = $('#activity-chart');
    if (!canvas) return;
    const empty = $('#chart-empty');
    const hasData = series.some(row => safeNum(row.events) > 0);
    empty.hidden = hasData;
    const rect = canvas.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const ratio = Math.max(1, window.devicePixelRatio || 1);
    canvas.width = Math.round(rect.width * ratio);
    canvas.height = Math.round(rect.height * ratio);
    const ctx = canvas.getContext('2d');
    ctx.scale(ratio, ratio);
    const w = rect.width, h = rect.height;
    const style = getComputedStyle(document.body);
    const grid = style.getPropertyValue('--line').trim() || '#e6eaf0';
    const muted = style.getPropertyValue('--muted').trim() || '#718096';
    const blue = style.getPropertyValue('--blue').trim() || '#5267e8';
    const red = style.getPropertyValue('--red').trim() || '#dc5b69';
    ctx.clearRect(0, 0, w, h);
    const left = 32, right = 8, top = 10, bottom = 25;
    const plotW = w - left - right, plotH = h - top - bottom;
    const peak = Math.max(1, ...series.map(row => safeNum(row.events)));
    ctx.lineWidth = 1;
    ctx.strokeStyle = grid;
    ctx.fillStyle = muted;
    ctx.font = '9px system-ui';
    for (let i = 0; i < 4; i++) {
      const y = top + (plotH * i / 3);
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(w - right, y); ctx.stroke();
      ctx.textAlign = 'right';
      ctx.fillText(fmt(Math.round(peak * (1 - i / 3))), left - 7, y + 3);
    }
    const slot = plotW / Math.max(1, series.length);
    const bw = Math.max(2, Math.min(12, slot * .56));
    series.forEach((row, index) => {
      const x = left + index * slot + (slot - bw) / 2;
      const height = plotH * safeNum(row.events) / peak;
      const alertHeight = plotH * safeNum(row.alerts) / peak;
      ctx.fillStyle = blue;
      roundedRect(ctx, x, top + plotH - height, bw, height, 3);
      if (alertHeight > 0) {
        ctx.fillStyle = red;
        roundedRect(ctx, x, top + plotH - alertHeight, bw, Math.max(2, alertHeight), 3);
      }
      const every = Math.ceil(series.length / 6);
      if (index % every === 0 || index === series.length - 1) {
        const label = String(row.hour || '').slice(11, 16) || String(index);
        ctx.fillStyle = muted; ctx.textAlign = 'center';
        ctx.fillText(label, x + bw / 2, h - 6);
      }
    });
  }

  function roundedRect(ctx, x, y, width, height, radius) {
    if (height <= 0) return;
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath(); ctx.fill();
  }

  function renderBreakdown(items) {
    const root = $('#class-breakdown');
    root.replaceChildren();
    if (!items.length) { root.append(textNode('p','empty-text','No flow alerts in this period.')); return; }
    const max = Math.max(1, ...items.map(item => safeNum(item.count)));
    items.slice(0, 6).forEach(item => {
      const row = textNode('div','breakdown-row');
      row.append(textNode('span','breakdown-label',pretty(item.name)));
      const track = textNode('div','breakdown-track');
      const fill = textNode('div','breakdown-fill');
      setBarWidth(fill, safeNum(item.count) / max);
      track.append(fill); row.append(track);
      row.append(textNode('span','breakdown-value',fmt(item.count)));
      root.append(row);
    });
  }

  function renderEvents() {
    const root = $('#event-rows');
    if (!root) return;
    const query = ($('#event-search')?.value || '').trim().toLowerCase();
    const limit = Number($('#event-limit')?.value || 100);
    const items = latestEvents.filter(item => eventFilter === 'all' || String(item.alert) === eventFilter)
      .filter(item => !query || [item.event_id,item.predicted_class,item.reason,item.source]
        .some(value => String(value || '').toLowerCase().includes(query))).slice(0, limit);
    root.replaceChildren();
    if (!items.length) {
      const row = document.createElement('tr');
      const cell = textNode('td','empty-cell',query ? 'No events match this search.' : 'No flow events received yet.');
      cell.colSpan = 7; row.append(cell); root.append(row);
    } else items.forEach(item => root.append(eventRow(item)));
    $('#event-count').textContent = `${fmt(items.length)} events shown`;
  }

  function eventRow(item) {
    const row = document.createElement('tr');
    row.tabIndex = 0;
    row.setAttribute('role','button');
    row.setAttribute('aria-label',`${item.alert ? 'Alert' : 'Flow'} ${item.event_id}, ${pretty(item.predicted_class)}`);
    const values = [
      textNode('span','event-id',item.event_id),
      textNode('span','class-chip',pretty(item.predicted_class)),
      textNode('span','signal-chip',pretty(item.reason)),
      textNode('span','score-value',safeNum(item.score).toFixed(3)),
      textNode('span','',item.source || 'unspecified'),
      textNode('span','',shortTime(item.received_at)),
      textNode('span',`status-chip ${item.alert ? 'alert' : 'benign'}`,item.alert ? 'Review' : 'Scored')
    ];
    values.forEach(value => { const cell=document.createElement('td'); cell.append(value); row.append(cell); });
    row.addEventListener('click', () => showEvent(item));
    row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); showEvent(item); } });
    return row;
  }

  function showEvent(item) {
    const root = $('#event-detail'); root.replaceChildren();
    root.append(textNode('p','eyebrow',item.alert ? 'FLOW ALERT' : 'FLOW SCORE'));
    root.append(textNode('h2','',pretty(item.predicted_class)));
    root.append(textNode('p','muted',`${item.reason} · ${shortTime(item.received_at)}`));
    const grid = textNode('div','detail-grid');
    [['Event ID',item.event_id],['Alert score',safeNum(item.score).toFixed(4)],['Source',item.source],['Model',item.model_version],['Signal type',item.reason],['Predicted class',pretty(item.predicted_class)]].forEach(([label,value])=>{
      const cell=textNode('div','detail-item'); cell.append(textNode('small','',label),textNode('strong','',value || '—')); grid.append(cell);
    });
    root.append(grid);
    const signals = textNode('div','signal-list');
    Object.entries(item.signals || {}).forEach(([name,value])=>signals.append(textNode('span',`signal-chip ${value?'signal-on':''}`,`${pretty(name)}: ${value?'yes':'no'}`)));
    root.append(signals);
    dialog.showModal();
  }

  function renderFindings() {
    const root = $('#finding-rows');
    if (!root) return;
    const filter = $('#provider-filter').value;
    const items = latestFindings.filter(item => filter === 'all' || item.provider === filter);
    root.replaceChildren();
    if (!items.length) {
      const row=document.createElement('tr'); const cell=textNode('td','empty-cell','No provider findings received yet.'); cell.colSpan=6;row.append(cell);root.append(row);
    } else items.slice(0,100).forEach(item=>{
      const row=document.createElement('tr');
      const severity=textNode('span',`severity-chip severity-${item.severity}`,pretty(item.severity));
      [[severity],[textNode('span','',item.title)],[textNode('span','provider-badge',item.provider)],[textNode('span','',item.resource || '—')],[textNode('span','',pretty(item.category))],[textNode('span','',shortTime(item.received_at))]].forEach(([value])=>{const cell=document.createElement('td');cell.append(value);row.append(cell);});
      row.tabIndex=0;row.title=item.description || item.title;
      row.addEventListener('click',()=>showFinding(item));
      root.append(row);
    });
    $('#finding-count').textContent = `${fmt(items.length)} findings`;
  }

  function showFinding(item) {
    const root=$('#event-detail');root.replaceChildren();
    root.append(textNode('p','eyebrow',`${pretty(item.provider)} NATIVE FINDING`));
    root.append(textNode('h2','',item.title));
    root.append(textNode('p','muted',item.description || 'No description provided by source.'));
    const grid=textNode('div','detail-grid');
    [['Severity',pretty(item.severity)],['Category',pretty(item.category)],['Resource',item.resource],['Finding ID',item.finding_id],['Occurred',shortTime(item.occurred_at)],['Received',shortTime(item.received_at)]].forEach(([label,value])=>{const cell=textNode('div','detail-item');cell.append(textNode('small','',label),textNode('strong','',value||'—'));grid.append(cell);});
    root.append(grid);dialog.showModal();
  }

  function renderProviderSummary(providers) {
    const root=$('#provider-summary');root.replaceChildren();
    const rows=Object.entries(providers);
    $('#stat-findings').textContent=fmt(rows.reduce((sum,[,count])=>sum+safeNum(count),0));
    if(!rows.length){root.append(textNode('p','empty-text','No provider findings received.'));return;}
    rows.forEach(([provider,count])=>{const row=textNode('div','provider-line');row.append(textNode('span','provider-badge',provider),textNode('strong','',`${fmt(count)} findings`));root.append(row);});
  }

  function renderRecentAlerts() {
    const root=$('#recent-alerts'); if(!root)return;
    const items=latestEvents.filter(item=>item.alert).slice(0,5);root.replaceChildren();
    if(!items.length){root.append(textNode('p','empty-text','No alerts recorded yet.'));return;}
    items.forEach(item=>{
      const row=textNode('button','recent-row');row.type='button';
      row.append(textNode('span','event-glyph','!'));
      const main=textNode('span','recent-main');
      main.append(textNode('strong','',`${pretty(item.predicted_class)} / ${pretty(item.reason)}`),
                  textNode('small','',`${item.source} / ${shortTime(item.received_at)}`));
      row.append(main);
      const score=textNode('span','recent-score',safeNum(item.score).toFixed(3));row.append(score);
      row.addEventListener('click',()=>showEvent(item));root.append(row);
    });
  }

  function renderModels(meta) {
    const root=$('#model-cards');root.replaceChildren();
    const metrics=meta.benchmark||{};
    const cards=[
      ['RF','Random Forest','Supervised known-attack classifier','Included','Hybrid-OR'],
      ['X','XGBoost','Supervised known-attack classifier',null,'Backend'],
      ['AE','Autoencoder','Benign-trained reconstruction anomaly score',null,'Training'],
      ['K','Benign K-means','Nearest-cluster distance anomaly signal',null,'Clusters']
    ];
    cards.forEach(([symbol,title,desc,value,label])=>{
      const card=textNode('article','model-card');card.append(textNode('span','model-symbol',symbol),textNode('h2','',title),textNode('p','',desc));
      const fallback=title==='XGBoost'?'xgboost':title==='Autoencoder'?'benign-only':'8';
      const display=typeof value==='number'?pct(value):(value||fallback);
      const kpi=textNode('div','model-kpi');kpi.append(textNode('span','',label),textNode('strong','',display));card.append(kpi);root.append(card);
    });
    const info=[
      ['Dataset',pretty(meta.dataset)],['Feature inputs',fmt(meta.features)],['Target validation FPR',meta.target_fpr==null?'—':pct(meta.target_fpr)],
      ['Test accuracy',metrics.accuracy==null?'—':pct(metrics.accuracy)],['Hybrid recall',metrics.recall==null?'—':pct(metrics.recall)],
      ['Hybrid false-positive rate',metrics.fpr==null?'—':pct(metrics.fpr)],['Test attack mix',meta.test_attack_prevalence==null?'—':pct(meta.test_attack_prevalence)],
      ['Test protocol',meta.official_test_partition?'Official holdout':'Random holdout']
    ];
    const metaPanel=$('#model-benchmark');metaPanel.replaceChildren();
    const head=textNode('div','panel-heading');const headContent=textNode('div','');
    headContent.append(textNode('h2','',`Benchmark snapshot / ${pretty(meta.evaluation_profile)} run`),
                       textNode('p','',`Metrics from ${pretty(meta.dataset)}; not a deployment guarantee.`));
    head.append(headContent);metaPanel.append(head);
    const grid=textNode('div','detail-grid');info.forEach(([name,value])=>{const cell=textNode('div','detail-item');cell.append(textNode('small','',name),textNode('strong','',value));grid.append(cell);});metaPanel.append(grid);
    const recallRoot=$('#heldout-chart');recallRoot.replaceChildren();
    const held=Object.entries(meta.heldout_recall||{}).sort((a,b)=>a[1]-b[1]);
    if(!held.length){recallRoot.append(textNode('p','empty-text','Held-out-family metrics unavailable.'));return;}
    const max=Math.max(1,...held.map(([,value])=>safeNum(value)));
    held.forEach(([name,value])=>{const row=textNode('div','breakdown-row');row.append(textNode('span','breakdown-label',pretty(name)));const track=textNode('div','breakdown-track');const fill=textNode('div','breakdown-fill');setBarWidth(fill,value/max);track.append(fill);row.append(track,textNode('span','breakdown-value',pct(value)));recallRoot.append(row);});
  }

  function renderRecent() { renderRecentAlerts(); }

  function navigate(page) {
    const valid = ['overview','events','findings','models','integrations','settings','about'];
    if(!valid.includes(page))page='overview';
    $$('.page-view').forEach(view=>view.classList.toggle('active',view.dataset.view===page));
    $$('.nav-link[data-page]').forEach(link=>link.classList.toggle('active',link.dataset.page===page));
    const title=({overview:'Overview',events:'Flow events',findings:'Cloud findings',models:'Models & analysis',integrations:'Integrations',settings:'Settings',about:'About CloudIDS'})[page];
    $('#breadcrumb-page').textContent=title;
    if(location.hash!==`#${page}`)history.replaceState(null,'',`#${page}`);
    $('#sidebar').classList.remove('open');
    if(page==='events')renderEvents();
    if(page==='findings')renderFindings();
    if(page==='overview')renderRecent();
  }

  $('#connect-form').addEventListener('submit',event=>{event.preventDefault();connect($('#api-token').value);});
  $('#disconnect-button').addEventListener('click',disconnect);
  $('#settings-disconnect').addEventListener('click',disconnect);
  $('#refresh-button').addEventListener('click',()=>refreshAll().then(()=>showToast('Dashboard refreshed')).catch(handleApiError));
  $$('[data-action="refresh"]').forEach(button=>button.addEventListener('click',()=>refreshAll().catch(handleApiError)));
  $$('.nav-link[data-page]').forEach(link=>link.addEventListener('click',event=>{event.preventDefault();navigate(link.dataset.page);}));
  $('#menu-button').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
  $('#range-select').addEventListener('change',()=>refreshAll().catch(handleApiError));
  $('#event-search').addEventListener('input',renderEvents);
  $('#event-limit').addEventListener('change',renderEvents);
  $('#provider-filter').addEventListener('change',renderFindings);
  $$('[data-event-filter]').forEach(button=>button.addEventListener('click',()=>{
    eventFilter=button.dataset.eventFilter;$$('[data-event-filter]').forEach(item=>item.classList.toggle('active',item===button));renderEvents();
  }));
  $('#theme-button').addEventListener('click',()=>setTheme(document.body.dataset.theme==='dark'?'light':'dark'));
  $('#theme-select').addEventListener('change',event=>setTheme(event.target.value));
  $('#poll-select').addEventListener('change',event=>{localStorage.setItem('cloudids-poll',event.target.value);startPolling();showToast('Refresh preference saved');});
  $$('[data-copy]').forEach(button=>button.addEventListener('click',async()=>{
    try{await navigator.clipboard.writeText(`${location.origin}${button.dataset.copy}`);showToast('Endpoint copied');}
    catch(_){showToast('Copy is unavailable in this browser');}
  }));
  dialog.addEventListener('click',event=>{if(event.target===dialog)dialog.close();});
  window.addEventListener('resize',()=>drawChart(lastAnalytics?.series||[]));
  window.addEventListener('hashchange',()=>navigate(location.hash.slice(1)));
  window.addEventListener('keydown',event=>{if(event.key==='Escape')$('#sidebar').classList.remove('open');});

  setTheme(localStorage.getItem('cloudids-theme')||'light');
  $('#poll-select').value=localStorage.getItem('cloudids-poll')||'10';
  setConnection(false,'Connect with a local API token');
})();
