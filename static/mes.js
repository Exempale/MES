// MES Pro+
// - Chunked transfer with progress bars (up to very large files)
// - Text, images, files, voice messages with stronger disguise (robot / simple pitch)
// - Local persistence; "End chat" button
// Security: demo-level AES-GCM with PBKDF2 key; server relays only.

const qs = new URLSearchParams(location.hash.slice(1));
const pathParts = location.pathname.split('/').filter(Boolean);
let roomId = pathParts[0] === 'room' ? pathParts[1] : null;

const els = {
  statusDot: document.getElementById('statusDot'),
  statusText: document.getElementById('statusText'),
  onlineCount: document.getElementById('onlineCount'),
  createRoom: document.getElementById('createRoom'),
  copyInvite: document.getElementById('copyInvite'),
  endChat: document.getElementById('endChat'),
  nickname: document.getElementById('nickname'),
  input: document.getElementById('input'),
  send: document.getElementById('send'),
  messages: document.getElementById('messages'),
  fileInput: document.getElementById('fileInput'),
  voiceBtn: document.getElementById('voiceBtn'),
  voiceEffect: document.getElementById('voiceEffect'),
  themeToggle: document.getElementById('themeToggle'),
  emptyState: document.getElementById('emptyState'),
  openCalls: document.getElementById('openCalls'),
  typingIndicator: document.getElementById('typingIndicator'),
};

let ws = null;
let key = null;
let secretB = null;
let saltB = null;
let meId = randomId(6);

// local persistence (IndexedDB + legacy fallback)
function storageKey(room){ return `MES_${room}`; }
let historyCache = [];
let assembling = new Map(); // fileId -> { total, got, chunks:Uint8Array[], meta, gotBytes }
const CHUNK_SIZE = 256 * 1024; // 256 KiB

// IndexedDB helpers
let idb = null;
function idbOpen(){
  return new Promise((resolve)=>{
    try {
      const req = indexedDB.open('MES_DB', 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('messages')) {
          const os = db.createObjectStore('messages', { keyPath: 'id' });
          os.createIndex('room', 'room', { unique: false });
          os.createIndex('ts', 'ts', { unique: false });
        }
        if (!db.objectStoreNames.contains('blobs')) {
          db.createObjectStore('blobs', { keyPath: 'id' });
        }
      };
      req.onsuccess = () => { idb = req.result; resolve(true); };
      req.onerror = () => resolve(false);
    } catch(_) { resolve(false); }
  });
}
// Progress helpers
const progressInfo = new Map(); // id -> { startTs, totalBytes, sentBytes }

function ensureProgressInfo(id, totalBytes){
  if (!progressInfo.has(id)) progressInfo.set(id, { startTs: Date.now(), totalBytes: totalBytes||0, sentBytes: 0 });
}
function renderProgressRow(el, id){
  const info = progressInfo.get(id);
  if (!info) return;
  const pct = info.totalBytes > 0 ? Math.min(100, Math.max(0, Math.round((info.sentBytes/info.totalBytes)*100))) : Math.round(parseFloat(el.querySelector('.progress>span')?.style.width||'0'));
  const elapsed = (Date.now() - info.startTs)/1000;
  const speed = elapsed>0 ? info.sentBytes / elapsed : 0; // bytes/sec
  const remain = Math.max(0, (info.totalBytes||0) - info.sentBytes);
  const etaSec = speed>0 ? Math.ceil(remain / speed) : 0;
  const etaStr = speed>0 ? `~${etaSec}s` : '—';
  const row = el.querySelector('.progress-row');
  if (row) row.innerHTML = `<span class="pct">${pct}%</span><span class="eta">${etaStr}</span>`;
}

function idbTx(store, mode='readonly'){
  return idb.transaction(store, mode).objectStore(store);
}
async function idbSaveMessage(msg){
  if (!idb) return;
  try { await new Promise((res,rej)=>{ const r=idbTx('messages','readwrite').put(msg); r.onsuccess=res; r.onerror=rej; }); } catch(_) {}
}
async function idbLoadMessages(room){
  if (!idb) return [];
  return new Promise((res)=>{
    try {
      const idx = idbTx('messages').index('room');
      const req = idx.getAll(room);
      req.onsuccess = () => { const arr = req.result || []; arr.sort((a,b)=>(a.ts||0)-(b.ts||0)); res(arr); };
      req.onerror = () => res([]);
    } catch(_) { res([]); }
  });
}
async function idbSaveBlob(id, bytes){
  if (!idb) return;
  try { await new Promise((res,rej)=>{ const r=idbTx('blobs','readwrite').put({ id, bytes }); r.onsuccess=res; r.onerror=rej; }); } catch(_) {}
}
async function idbGetBlob(id){
  if (!idb) return null;
  return new Promise((res)=>{
    try { const r=idbTx('blobs').get(id); r.onsuccess=()=>res(r.result?.bytes||null); r.onerror=()=>res(null); } catch(_) { res(null); }
  });
}

init().catch(console.error);

async function init() {
  // Theme: restore preference or follow system
  initTheme();

  await idbOpen();
  if (roomId) {
    const fromIdb = await idbLoadMessages(roomId);
    if (fromIdb.length) {
      historyCache = fromIdb;
      for (const item of historyCache) renderMessage(item, item.sender === meId, true);
    } else {
      const saved = localStorage.getItem(storageKey(roomId));
      if (saved) {
        try {
          historyCache = JSON.parse(saved);
          for (const item of historyCache) renderMessage(item, item.sender === meId, true);
        } catch(_) {}
      }
    }
  }
  updateEmptyState();

  const fromHashK = qs.get('k');
  const fromHashS = qs.get('s');
  if (!fromHashK || !fromHashS || !roomId) {
    setOffline();
  } else {
    secretB = base64urlToBytes(fromHashK);
    saltB = base64urlToBytes(fromHashS);
    key = await deriveKey(secretB, saltB);
    connect();
  }

  els.createRoom.onclick = async () => {
    roomId = randomId(12);
    secretB = crypto.getRandomValues(new Uint8Array(32));
    saltB = crypto.getRandomValues(new Uint8Array(16));
    key = await deriveKey(secretB, saltB);
    const url = `${location.origin}/room/${roomId}#k=${bytesToBase64url(secretB)}&s=${bytesToBase64url(saltB)}`;
    history.pushState({}, '', url);
    historyCache = [];
    localStorage.removeItem(storageKey(roomId));
    // Clear UI messages for the new room
    els.messages.innerHTML = '';
    updateEmptyState();
    connect();
  };

  els.copyInvite.onclick = async () => {
    if (!roomId || !secretB || !saltB) return alert('Сначала создайте комнату');
    const url = `${location.origin}/room/${roomId}#k=${bytesToBase64url(secretB)}&s=${bytesToBase64url(saltB)}`;
    await navigator.clipboard.writeText(url);
    notify('Ссылка скопирована');
  };

  els.endChat.onclick = () => {
    if (!roomId) return;
    localStorage.removeItem(storageKey(roomId));
    location.href = `${location.origin}/room/${roomId}`;
  };

  els.send.onclick = sendText;
  els.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendText(); }
  });

  // Auto-resize textarea
  els.input.addEventListener('input', autoResizeTextarea);
  autoResizeTextarea();

  // typing indicator
  let typingTimer=null, lastTypingSent=0;
  els.input.addEventListener('input', ()=>{
    showTyping(true, els.nickname.value || 'anon');
    if (Date.now()-lastTypingSent>1500){ lastTypingSent=Date.now(); sendTyping(true); }
    clearTimeout(typingTimer);
    typingTimer = setTimeout(()=>{ showTyping(false); sendTyping(false); }, 2000);
  });

  els.fileInput.addEventListener('change', handleFiles);
  els.voiceBtn.addEventListener('click', handleVoice);

  // Theme toggle
  if (els.themeToggle) {
    els.themeToggle.addEventListener('click', toggleTheme);
    reflectThemeIcon();
  }

  // Open calls window/tab
  if (els.openCalls){
    els.openCalls.onclick = () => openCallsWindow();
  }
}

function setOnline(){ els.statusDot.classList.add('online'); els.statusText.textContent='online'; }
function setOffline(){ els.statusDot.classList.remove('online'); els.statusText.textContent='offline'; }

function notify(txt) {
  const li = document.createElement('li');
  li.className = 'meta';
  li.textContent = txt;
  els.messages.appendChild(li);
  els.messages.scrollTop = els.messages.scrollHeight;
  updateEmptyState();
}

function randomId(n) {
  const arr = crypto.getRandomValues(new Uint8Array(n));
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out=''; for (let b of arr) out += alphabet[b % alphabet.length];
  return out;
}

async function deriveKey(secretBytes, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey('raw', secretBytes, {name: 'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name: 'PBKDF2', salt: saltBytes, iterations: 200_000, hash: 'SHA-256'},
    keyMaterial,
    {name: 'AES-GCM', length: 256},
    false,
    ['encrypt', 'decrypt']
  );
}

function connect() {
  if (!roomId) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const wsUrl = `${proto}://${location.host}/ws/${roomId}`;
  ws = new WebSocket(wsUrl);

  ws.onopen = () => { setOnline(); notify(`Подключено к комнате ${roomId}`); };
  ws.onclose = () => { setOffline(); notify('Соединение закрыто'); };
  ws.onerror = () => { setOffline(); notify('Ошибка соединения'); };

  ws.onmessage = async (ev) => {
    let dataStr = typeof ev.data === 'string' ? ev.data : await ev.data.text();
    try {
      const data = JSON.parse(dataStr);
      if (data && data._control === 'online') {
        els.onlineCount.textContent = String(data.count);
        return;
      }
    } catch(_) {}

    // Encrypted packet
    try {
      const packet = JSON.parse(dataStr);
      if (!packet.ct || !packet.iv) return;
      const iv = base64urlToBytes(packet.iv);
      const ct = base64urlToBytes(packet.ct);
      const dec = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, ct);
      const str = new TextDecoder().decode(new Uint8Array(dec));
      const msg = JSON.parse(str);
      // Ignore WebRTC signaling messages here (handled by calls.html)
      if (msg && msg._rtc) return;
      if (msg && msg._typing) { onTypingSignal(msg.sender, msg._typing); return; }
      onDecryptedMessage(msg);
    } catch(e) {
      // ignore
    }
  };
}

function onDecryptedMessage(msg){
  // ignore service messages (typing) from rendering in chat list
  if (msg && msg._typing) return;
  if (msg.kind === 'chunk') {
    const id = msg.fileId;
    if (!assembling.has(id)) {
      assembling.set(id, { total: msg.total, got: 0, chunks: new Array(msg.total), meta: msg.meta, gotBytes: 0 });
    }
    const entry = assembling.get(id);
    const bytes = base64urlToBytes(msg.data);
    entry.chunks[msg.seq] = bytes;
    entry.got++;
    entry.gotBytes += bytes.length;
    updateProgress(id, entry.got / entry.total, false);
    if (entry.got === entry.total) {
      // assemble bytes
      const meta = entry.meta;
      const totalBytes = entry.chunks.reduce((s,b)=> s + (b?.length||0), 0);
      const joined = new Uint8Array(totalBytes);
      let p=0; for (const part of entry.chunks){ if (!part) continue; joined.set(part, p); p+=part.length; }
      const payload = { id, kind: meta.kind, sender: msg.sender, nick: msg.nick, ts: msg.ts, name: meta.name, mime: meta.mime, size: meta.size, hasBlob: true };
      addMessage(payload, false);
      idbSaveBlob(id, joined);
      assembling.delete(id);
    }
    return;
  }
  // regular messages (text)
  addMessage(msg, false);
}

function nowPayloadBase(type, extra={}){
  return {
    id: crypto.randomUUID(),
    kind: type, // 'text' | 'image' | 'file' | 'audio' | 'chunk'
    sender: meId,
    nick: els.nickname.value.trim().slice(0, 24) || 'anon',
    ts: Date.now(),
    ...extra,
  };
}

async function encryptAndSend(payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) { notify('Нет соединения'); return; }
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, bytes);
  const packet = { iv: bytesToBase64url(iv), ct: bytesToBase64url(new Uint8Array(ct)) };
  ws.send(JSON.stringify(packet));
}

// ---- Calls moved to calls.html ----
function openCallsWindow(){
  let k = qs.get('k');
  let s = qs.get('s');
  const nick = (els.nickname.value||'').slice(0,24);
  // If room or keys are missing, create them on the fly
  const ensure = async () => {
    if (!roomId || !k || !s) {
      roomId = roomId || randomId(12);
      const sec = crypto.getRandomValues(new Uint8Array(32));
      const sal = crypto.getRandomValues(new Uint8Array(16));
      secretB = sec; saltB = sal; k = bytesToBase64url(sec); s = bytesToBase64url(sal);
      key = await deriveKey(secretB, saltB);
      const url = `${location.origin}/room/${roomId}#k=${k}&s=${s}`;
      history.pushState({}, '', url);
      connect();
    }
  };
  (async () => {
    try { await ensure(); } catch(_){}
    const url = `${location.origin}/static/calls.html?room=${encodeURIComponent(roomId||'')}&nick=${encodeURIComponent(nick)}#k=${encodeURIComponent(k||'')}&s=${encodeURIComponent(s||'')}`;
    window.open(url, '_blank');
  })();
}

// Mute/unmute and device switching
function attachTrackStateButtons(){
  if (!els.toggleMic || !els.toggleCam) return;
  els.toggleMic.onclick = () => {
    if (!localStream) return;
    for (const t of localStream.getAudioTracks()) t.enabled = !t.enabled;
    els.toggleMic.textContent = localStream.getAudioTracks().some(t=>t.enabled) ? 'Микрофон' : 'Микрофон (выкл)';
  };
  els.toggleCam.onclick = () => {
    if (!localStream) return;
    for (const t of localStream.getVideoTracks()) t.enabled = !t.enabled;
    els.toggleCam.textContent = localStream.getVideoTracks().some(t=>t.enabled) ? 'Камера' : 'Камера (выкл)';
  };
}
async function populateDevices(){
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    if (els.micSelect){
      els.micSelect.innerHTML = '';
      for (const d of devices.filter(d=>d.kind==='audioinput')){
        const opt = document.createElement('option'); opt.value=d.deviceId; opt.textContent=d.label||'Микрофон'; els.micSelect.appendChild(opt);
      }
      els.micSelect.onchange = async ()=>{ await switchDevice({audio: {deviceId:{exact: els.micSelect.value}}, video: !!(localStream && localStream.getVideoTracks().length)}); };
    }
    if (els.camSelect){
      els.camSelect.innerHTML = '';
      for (const d of devices.filter(d=>d.kind==='videoinput')){
        const opt = document.createElement('option'); opt.value=d.deviceId; opt.textContent=d.label||'Камера'; els.camSelect.appendChild(opt);
      }
      els.camSelect.onchange = async ()=>{ await switchDevice({audio: !!(localStream && localStream.getAudioTracks().length), video: {deviceId:{exact: els.camSelect.value}}}); };
    }
  } catch(_){}
}
async function switchDevice(constraints){
  if (!pc) return startCall({audio:true, video: !!constraints.video});
  const newStream = await navigator.mediaDevices.getUserMedia(constraints);
  for (const track of newStream.getTracks()){
    const sender = pc.getSenders().find(s=>s.track && s.track.kind===track.kind);
    if (sender) await sender.replaceTrack(track);
  }
  newStream.getTracks().forEach(t=>localStream.addTrack(t));
  if (els.localVideo) els.localVideo.srcObject = localStream;
}

// Typing indicator
const typingMap = new Map(); // senderId -> { nick, untilTs }
function renderTyping(){
  if (!els.typingIndicator) return;
  const now = Date.now();
  for (const [k,v] of typingMap){ if (v.untilTs < now) typingMap.delete(k); }
  if (typingMap.size === 0){ els.typingIndicator.style.display='none'; els.typingIndicator.textContent=''; return; }
  const names = Array.from(typingMap.values()).map(v=>v.nick||'anon');
  const label = names.length===1 ? `${names[0]} печатает…` : `${names.slice(0,3).join(', ')}${names.length>3?' и др.':''} печатают…`;
  els.typingIndicator.style.display='block';
  els.typingIndicator.textContent = label;
}
function showTyping(on, nick){
  // keep single-user helper for local echo
  if (!els.typingIndicator) return;
  if (!on){ els.typingIndicator.style.display='none'; els.typingIndicator.textContent=''; return; }
  els.typingIndicator.style.display='block';
  els.typingIndicator.textContent = `${nick||'anon'} печатает…`;
}
async function sendTyping(on){ const payload = nowPayloadBase('text', { text:'', _typing: { on, nick: (els.nickname.value||'anon').slice(0,24) } }); await encryptAndSend(payload); }
function onTypingSignal(senderId, obj){
  const name = (obj && obj.nick) ? obj.nick : 'anon';
  if (obj && obj.on){
    typingMap.set(senderId, { nick: name, untilTs: Date.now()+3000 });
  } else {
    typingMap.delete(senderId);
  }
  renderTyping();
  if (obj && obj.on){ setTimeout(renderTyping, 3100); }
}

async function sendText() {
  const text = els.input.value.trim();
  if (!text) return;
  els.input.value = '';
  const payload = nowPayloadBase('text', { text });
  addMessage(payload, true);
  await encryptAndSend(payload);
}

async function handleFiles(ev){
  const files = Array.from(ev.target.files || []);
  ev.target.value = '';
  for (const file of files) {
    await sendLargeBlob(file, file.type.startsWith('image/') ? 'image' : 'file');
  }
}

async function sendLargeBlob(file, kind){
  const fileId = crypto.randomUUID();
  const meta = { name: file.name, mime: file.type || 'application/octet-stream', size: file.size, kind };
  const total = Math.ceil(file.size / CHUNK_SIZE);
  // optimistic placeholder with progress
  createProgressCard(fileId, meta, true);
  const byteChunks = [];
  ensureProgressInfo(fileId, file.size);
  for (let offset=0, seq=0; offset < file.size; offset += CHUNK_SIZE, seq++) {
    const blobPart = file.slice(offset, Math.min(file.size, offset + CHUNK_SIZE));
    const buf = new Uint8Array(await blobPart.arrayBuffer());
    byteChunks.push(buf);
    const b64 = bytesToBase64url(buf);
    const chunkMsg = nowPayloadBase('chunk', {
      fileId, seq, total, meta, data: b64
    });
    updateProgress(fileId, (seq+1)/total, true);
    await encryptAndSend(chunkMsg);
    const info = progressInfo.get(fileId); if (info) { info.sentBytes = Math.min(file.size, (seq+1)*CHUNK_SIZE); renderProgressRow(document.getElementById(`progress-${fileId}`), fileId); }
  }
  // assemble locally for persistence and immediate render
  const totalBytes = byteChunks.reduce((s,b)=>s+b.length,0);
  const merged = new Uint8Array(totalBytes);
  let off=0; for (const b of byteChunks){ merged.set(b, off); off+=b.length; }
  const donePayload = nowPayloadBase(kind, { name: meta.name, mime: meta.mime, size: meta.size, hasBlob: true });
  donePayload.id = fileId;
  addMessage(donePayload, true);
  await idbSaveBlob(fileId, merged);
  removeProgressCard(fileId);
}

function createProgressCard(id, meta, mine){
  const li = document.createElement('li');
  li.className = 'msg' + (mine ? ' me' : '');
  li.id = `progress-${id}`;
  const metaDiv = document.createElement('div');
  metaDiv.className = 'meta';
  metaDiv.textContent = `${els.nickname.value || 'anon'} • отправка ${meta.name}…`;
  const body = document.createElement('div');
  body.innerHTML = `<div class="file">${meta.name} (${prettySize(meta.size)})</div>
    <div class="progress"><span style="width:0%"></span></div>
    <div class="progress-row"><span class="pct">0%</span><span class="eta">—</span></div>`;
  li.appendChild(metaDiv); li.appendChild(body);
  els.messages.appendChild(li);
  els.messages.scrollTop = els.messages.scrollHeight;
}
function updateProgress(id, frac, mine){
  const el = document.getElementById(`progress-${id}`);
  if (!el) return;
  const bar = el.querySelector('.progress>span');
  if (bar) bar.style.width = `${(Math.min(1, Math.max(0, frac))*100).toFixed(1)}%`;
  renderProgressRow(el, id);
}
function removeProgressCard(id){
  const el = document.getElementById(`progress-${id}`);
  if (el && el.parentNode) el.parentNode.removeChild(el);
}

// Voice recording with stronger disguise.
// We collect raw PCM via ScriptProcessor, then post-process:
// - robot: ring modulation + distortion
// - chipmunk: speed up 1.5x (higher pitch)
// - deep: slow 0.8x (lower pitch)
// Encoded as WAV (PCM16).

let recStream=null, recCtx=null, spNode=null, pcmL=[];

async function handleVoice(){
  if (spNode) { // stop
    stopRecording();
    return;
  }
  try {
    recStream = await navigator.mediaDevices.getUserMedia({audio: true});
    recCtx = new (window.AudioContext || window.webkitAudioContext)();
    const source = recCtx.createMediaStreamSource(recStream);
    spNode = recCtx.createScriptProcessor(4096, 1, 1);
    source.connect(spNode); spNode.connect(recCtx.destination);
    pcmL = [];
    spNode.onaudioprocess = (e) => {
      const ch = e.inputBuffer.getChannelData(0);
      pcmL.push(new Float32Array(ch));
    };
    els.voiceBtn.textContent = '🔴';
    notify('Запись начата… Нажмите ещё раз, чтобы остановить.');
  } catch(e){
    console.error(e); notify('Не удалось начать запись');
  }
}

async function stopRecording(){
  els.voiceBtn.textContent = '🎙️';
  spNode.disconnect(); spNode = null;
  recStream.getTracks().forEach(t => t.stop());
  const rate = recCtx.sampleRate;
  recCtx.close();
  // Join PCM
  let total = 0; for (const b of pcmL) total += b.length;
  const pcm = new Float32Array(total);
  let off=0; for (const b of pcmL) { pcm.set(b, off); off += b.length; }

  // Apply effect
  const mode = els.voiceEffect.value;
  let processed = pcm, outRate = rate;
  if (mode === 'robot') {
    processed = ringModulate(pcm, rate, 35); // 35 Hz ring modulation
    processed = softClip(processed, 2.5);
  } else if (mode === 'chipmunk') {
    const factor = 1.5;
    processed = resample(pcm, rate, rate*factor);
    outRate = rate; // we resampled then will encode at original rate -> higher pitch & shorter
  } else if (mode === 'deep') {
    const factor = 0.8;
    processed = resample(pcm, rate, rate*factor);
    outRate = rate;
  }

  // Encode WAV (PCM16)
  const wav = pcmToWav(processed, outRate);
  const bytes = new Uint8Array(wav);
  const b64 = bytesToBase64url(bytes);
  const payload = nowPayloadBase('audio', {
    name: `voice-${new Date().toISOString().replace(/[:.]/g,'-')}.wav`,
    mime: 'audio/wav',
    size: bytes.byteLength,
    data: b64
  });
  addMessage(payload, true);
  await encryptAndSend(payload);
}

// DSP helpers
function ringModulate(pcm, rate, freq){
  const out = new Float32Array(pcm.length);
  for (let i=0;i<pcm.length;i++){
    const mod = Math.sin(2*Math.PI*freq*(i/rate));
    out[i] = pcm[i]*mod;
  }
  return out;
}
function softClip(pcm, amount){
  const out = new Float32Array(pcm.length);
  for (let i=0;i<pcm.length;i++){
    const x = pcm[i]*amount;
    out[i] = Math.tanh(x);
  }
  return out;
}
function resample(pcm, inRate, outRate){
  const ratio = outRate / inRate;
  const n = Math.floor(pcm.length * (1/ratio));
  const out = new Float32Array(n);
  for (let i=0;i<n;i++){
    const srcIndex = i*ratio;
    const i0 = Math.floor(srcIndex);
    const i1 = Math.min(pcm.length-1, i0+1);
    const frac = srcIndex - i0;
    out[i] = pcm[i0]*(1-frac) + pcm[i1]*frac;
  }
  return out;
}
function pcmToWav(pcm, sampleRate){
  // 16-bit PCM mono
  const bytesPerSample = 2;
  const blockAlign = bytesPerSample * 1;
  const byteRate = sampleRate * blockAlign;
  const dataSize = pcm.length * bytesPerSample;
  const buffer = new ArrayBuffer(44 + dataSize);
  const dv = new DataView(buffer);
  let p = 0;
  function writeStr(s){ for (let i=0;i<s.length;i++) dv.setUint8(p++, s.charCodeAt(i)); }
  function writeU32(v){ dv.setUint32(p, v, true); p+=4; }
  function writeU16(v){ dv.setUint16(p, v, true); p+=2; }

  writeStr('RIFF'); writeU32(36 + dataSize); writeStr('WAVE');
  writeStr('fmt '); writeU32(16); writeU16(1); writeU16(1);
  writeU32(sampleRate); writeU32(byteRate); writeU16(blockAlign); writeU16(16);
  writeStr('data'); writeU32(dataSize);
  // samples
  let offset = 44;
  for (let i=0;i<pcm.length;i++){
    let s = Math.max(-1, Math.min(1, pcm[i]));
    dv.setInt16(offset, s < 0 ? s*0x8000 : s*0x7FFF, true);
    offset += 2;
  }
  return buffer;
}

function addMessage(msg, mine=false){
  const toStore = { ...msg, room: roomId };
  historyCache.push(toStore);
  // persist in IDB
  idbSaveMessage(toStore);
  // legacy fallback
  try { localStorage.setItem(storageKey(roomId), JSON.stringify(historyCache).slice(0, 4_000_000)); } catch(_) {}

  renderMessage(toStore, mine, false);
  // autoscroll to bottom when new message arrives
  els.messages.scrollTop = els.messages.scrollHeight;
  updateEmptyState();
}

function renderMessage(msg, mine=false, restoring=false){
  const li = document.createElement('li');
  li.className = 'msg' + (mine ? ' me' : '');
  const meta = document.createElement('div');
  meta.className = 'meta';
  const d = new Date(msg.ts || Date.now());
  meta.textContent = `${msg.nick || 'anon'} • ${d.toLocaleTimeString()}`;
  const body = document.createElement('div');

  if (msg.kind === 'text') {
    body.textContent = msg.text || '';
  } else if (msg.kind === 'image') {
    const img = document.createElement('img');
    img.className = 'preview';
    if (msg.hasBlob && !msg.data) {
      idbGetBlob(msg.id).then((bytes)=>{ if (!bytes) return; const blob=new Blob([bytes],{type: msg.mime||'image/*'}); img.src = URL.createObjectURL(blob); });
    } else {
      const bytes = base64urlToBytes(msg.data);
      const blob = new Blob([bytes], {type: msg.mime || 'image/*'});
      img.src = URL.createObjectURL(blob);
    }
    img.alt = msg.name || 'image';
    body.appendChild(img);

    const a = document.createElement('a');
    a.href = img.src; a.download = msg.name || 'image';
    a.textContent = `Скачать (${prettySize(msg.size)})`;
    a.className = 'file';
    body.appendChild(a);
  } else if (msg.kind === 'audio') {
    let url = '';
    if (msg.hasBlob && !msg.data) {
      // will fill asynchronously
    } else {
      const bytes = base64urlToBytes(msg.data);
      const blob = new Blob([bytes], {type: msg.mime || 'audio/wav'});
      url = URL.createObjectURL(blob);
    }
    const audio = document.createElement('audio');
    audio.controls = true; audio.src = url;
    body.appendChild(audio);

    const a = document.createElement('a');
    a.href = url; a.download = msg.name || 'voice.wav';
    a.textContent = `Скачать голосовое (${prettySize(msg.size)})`;
    a.className = 'file';
    body.appendChild(a);
    if (msg.hasBlob && !msg.data) {
      idbGetBlob(msg.id).then((bytes)=>{ if (!bytes) return; const blob=new Blob([bytes],{type: msg.mime||'audio/wav'}); const u=URL.createObjectURL(blob); audio.src=u; a.href=u; });
    }
  } else if (msg.kind === 'file') {
    let url = '';
    if (msg.hasBlob && !msg.data) {
      // will fill asynchronously
    } else {
      const bytes = base64urlToBytes(msg.data);
      const blob = new Blob([bytes], {type: msg.mime || 'application/octet-stream'});
      url = URL.createObjectURL(blob);
    }
    const a = document.createElement('a');
    a.href = url; a.download = msg.name || 'file.bin';
    a.textContent = `${msg.name || 'файл'} (${prettySize(msg.size)})`;
    body.appendChild(a);
    if (msg.hasBlob && !msg.data) {
      idbGetBlob(msg.id).then((bytes)=>{ if (!bytes) return; const blob=new Blob([bytes],{type: msg.mime||'application/octet-stream'}); const u=URL.createObjectURL(blob); a.href=u; });
    }
  } else {
    body.textContent = '[неизвестный тип]';
  }

  li.appendChild(meta); li.appendChild(body);
  els.messages.appendChild(li);
}

// UI helpers
function updateEmptyState(){
  if (!els.emptyState) return;
  const hasMessages = els.messages && els.messages.children && els.messages.children.length > 0;
  els.emptyState.style.display = hasMessages ? 'none' : 'flex';
}

function autoResizeTextarea(){
  if (!els.input) return;
  els.input.style.height = 'auto';
  const max = 180; // px
  const newH = Math.min(max, els.input.scrollHeight);
  els.input.style.height = newH + 'px';
}

// Theme management
function getSystemTheme(){
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
function loadTheme(){
  return localStorage.getItem('MES_THEME') || getSystemTheme();
}
function saveTheme(theme){
  try { localStorage.setItem('MES_THEME', theme); } catch(_) {}
}
function applyTheme(theme){
  document.documentElement.setAttribute('data-theme', theme);
  reflectThemeIcon();
}
function initTheme(){
  applyTheme(loadTheme());
  // React to system changes if user hasn't set explicit preference
  try {
    const mql = window.matchMedia('(prefers-color-scheme: light)');
    mql.addEventListener?.('change', () => {
      if (!localStorage.getItem('MES_THEME')) applyTheme(getSystemTheme());
    });
  } catch(_) {}
}
function toggleTheme(){
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
  saveTheme(next);
}
function reflectThemeIcon(){
  if (!els.themeToggle) return;
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  els.themeToggle.textContent = theme === 'light' ? '🌙' : '🌓';
}

function prettySize(n){
  if (!n && n !== 0) return '';
  const kb = 1024, mb = kb*1024;
  if (n >= mb) return (n/mb).toFixed(2) + ' MB';
  if (n >= kb) return (n/kb).toFixed(1) + ' KB';
  return n + ' B';
}

function bytesToBase64url(bytes) {
  let bin = '';
  for (let b of bytes) bin += String.fromCharCode(b);
  let b64 = btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  return b64;
}
function base64urlToBytes(s) {
  s = (s || '').replace(/-/g,'+').replace(/_/g,'/');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
