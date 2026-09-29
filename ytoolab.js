/**
 * Ytoo 机场考古工具箱 — Loon http-request 脚本
 * 触发: Safari 打开 http://ytoolab.local/  (明文 http, 无需 MITM)
 * 路由:
 *   /                       首页表单
 *   /probe?host=x&port=y    节点服务器全流程指纹 → FOFA/Quake 检索串
 *   /subcheck?url=<enc>     订阅端点验证 (subscription-userinfo/文件名/协议统计/节点名)
 *   /crt?q=domain           crt.sh 证书透明度域名族
 *   /revip?q=1.2.3.4        同 IP 反查
 *   /watch                  43.134.88.243:8080 复活检查
 */
const WATCH = 'http://43.134.88.243:8080/';
const FEATURES = /日用|高级\s?专线|YToo/i;

const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const b64e = s => btoa(unescape(encodeURIComponent(s)));

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · YtooLab</title><style>body{background:#0d1117;color:#e6edf3;font:14px/1.55 -apple-system,Menlo,monospace;margin:0;padding:16px;max-width:760px;margin:auto}h1{font-size:18px;color:#58a6ff}h2{font-size:15px;color:#79c0ff;margin:18px 0 6px}a{color:#58a6ff;word-break:break-all}.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px;margin:10px 0;overflow-x:auto}.kv{margin:3px 0}.kv b{color:#7ee787;font-weight:600}code{font-family:Menlo,monospace;font-size:12px;color:#ffa657;word-break:break-all}.hit{color:#f85149;font-weight:700}input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:8px;padding:8px;margin:4px 0;font-size:14px}button{background:#238636;color:#fff;border:0;border-radius:8px;padding:8px 16px;font-size:14px;margin-top:6px}.small{color:#8b949e;font-size:12px;margin:4px 0}</style></head><body><h1>🛰 Ytoo 机场考古工具箱</h1>${body}<p class="small">YtooLab · 明文 http 拦截 · 无需 MITM</p></body></html>`;
}

function req(opt) {
  return new Promise(res => {
    opt.timeout = opt.timeout || 12000;
    opt.policy = 'DIRECT';
    $httpClient[(opt.method || 'get').toLowerCase()](opt, (s, r, d) => res({ status: String(s || '0'), headers: r || {}, body: d == null ? '' : String(d) }));
  });
}

function parseUserinfo(h) {
  if (!h) return '';
  const o = {};
  h.split(';').forEach(p => { const i = p.split('='); if (i[1]) o[i[0].trim()] = Number(i[1].trim()); });
  const g = x => x ? (x / 1073741824).toFixed(2) + ' GB' : '?';
  const L = [];
  if (o.upload || o.download) L.push(`已用 ${g((o.upload || 0) + (o.download || 0))} (↑${g(o.upload)} ↓${g(o.download)})`);
  if (o.total) L.push(`总量 ${g(o.total)}`);
  if (o.expire) L.push(`到期 ${new Date(o.expire * 1000).toISOString().slice(0, 10)}`);
  return L.join(' · ') || h;
}

function analyzeBody(body) {
  let raw = body, wasB64 = false;
  const t = body.replace(/\s+/g, '');
  if (t.length > 80 && /^[A-Za-z0-9+/=]+$/.test(t)) {
    try {
      let dec = atob(t);
      try { dec = decodeURIComponent(escape(dec)); } catch (e) {}
      raw = dec; wasB64 = true;
    } catch (e) {}
  }
  const protos = {};
  ['anytls', 'vless', 'vmess://', 'trojan', 'ss://', 'ssr://', 'hysteria2', 'tuic'].forEach(p => { const n = raw.split(p).length - 1; if (n) protos[p.replace('://', '')] = n; });
  let names = [];
  try {
    const cn = [...raw.matchAll(/(?:^|\n)\s*-?\s*name:\s*["']?([^"'\n]{1,60})/g)].map(m => m[1].trim());
    const un = [...raw.matchAll(/#([^&\n\r]{1,60})/g)].map(m => decodeURIComponent(m[1]).trim());
    const jn = [...raw.matchAll(/"name"\s*:\s*"([^"]{1,60})"/g)].map(m => m[1].trim());
    names = [...new Set([...cn, ...un, ...jn])].filter(n => n && !/^(http|剩余|套餐|到期|官网)/i.test(n)).slice(0, 12);
  } catch (e) {}
  return { wasB64, protos, names, hit: FEATURES.test(raw), isClash: /proxies:/.test(raw), isSingbox: /"outbounds"/.test(raw) };
}

function fofaLink(q) { return `https://fofa.info/result?qbase64=${encodeURIComponent(b64e(q))}`; }
function quakeLink(q) { return `https://quake.360.net/quake/search?q=${encodeURIComponent(q)}`; }

function queryBlock(items) {
  return items.map(([q, note]) => `<div class="card"><div class="kv"><b>${esc(note)}</b></div><code>${esc(q)}</code><br><a href="${fofaLink(q)}">→ FOFA 搜这条</a> · <a href="${quakeLink(q)}">→ Quake 搜这条</a></div>`).join('');
}

async function doProbe(host, port) {
  const P = [];
  const dns = await req({ url: `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, timeout: 10000 });
  let ips = [];
  try { ips = (JSON.parse(dns.body).Answer || []).filter(a => a.type === 1).map(a => a.data); } catch (e) {}
  P.push(`<div class="card"><div class="kv"><b>DNS 解析</b></div><div class="kv">${esc(host)} → ${ips.length ? esc(ips.join(', ')) : '<span class="hit">无 A 记录/解析失败</span>'}</div></div>`);

  const targets = [
    [`http://${host}:${port}/`, 'HTTP 探测'],
    [`https://${host}:${port}/`, 'HTTPS 探测 (自签证书会失败, 正常)'],
    [`http://${host}/`, 'HTTP :80 探测'],
  ];
  let servers = [], cdSeen = '', uiSeen = '';
  for (const [u, label] of targets) {
    const r = await req({ url: u, timeout: 9000 });
    const hs = Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    const hh = {};
    Object.keys(r.headers).forEach(k => { hh[k.toLowerCase()] = String(r.headers[k]); });
    if (hh['server']) servers.push({ port: u.split('/')[2], server: hh['server'] });
    if (hh['content-disposition']) cdSeen = hh['content-disposition'];
    if (hh['subscription-userinfo']) uiSeen = hh['subscription-userinfo'];
    const bodySnip = r.body ? esc(r.body.slice(0, 180)).replace(/\n/g, ' ') : '';
    P.push(`<div class="card"><div class="kv"><b>${label}</b> <span class="small">${esc(u)}</span></div><div class="kv">状态: <code>${esc(r.status)}</code></div>${hs ? `<pre style="white-space:pre-wrap;margin:4px 0"><code>${esc(hs)}</code></pre>` : ''}${bodySnip ? `<div class="kv small">body: ${bodySnip}</div>` : ''}</div>`);
  }

  let crtHtml = '';
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const c = await req({ url: `https://crt.sh/?q=%25.${encodeURIComponent(host)}&output=json`, timeout: 20000 });
    let doms = [];
    try { const j = JSON.parse(c.body); doms = [...new Set(j.flatMap(x => String(x.name_value).split('\n')))].slice(0, 25); } catch (e) {}
    crtHtml = `<div class="card"><div class="kv"><b>证书透明度 (crt.sh)</b></div>${doms.length ? doms.map(d => `<div class="kv mono">${esc(d)}</div>`).join('') : `<div class="kv">crt.sh 无结果/超时 — <a href="https://crt.sh/?q=${encodeURIComponent(host)}">网页版查</a></div>`}</div>`;
    if (doms.length) {
      P.push('<h2>🎯 域名族检索串</h2>');
      P.push(queryBlock(doms.slice(0, 6).map(d => [`domain="${d}"`, '域名资产'])));
    }
  } else {
    const r = await req({ url: `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(host)}`, timeout: 12000 });
    const rev = (r.body || '').includes('error') || !r.body ? '' : r.body;
    P.push(`<div class="card"><div class="kv"><b>同 IP 反查 (hackertarget)</b></div><pre style="white-space:pre-wrap;margin:4px 0"><code>${esc(rev || '无限额/无结果 — 去 FOFA: ip="' + host + '"')}</code></pre></div>`);
  }

  P.push('<h2>🎯 检索串生成</h2>');
  const qs = [[`ip="${host}"`, '该 IP 全部资产']];
  if (port) qs.push([`ip="${host}" && port="${port}"`, 'IP+端口精确']);
  [...new Set(servers.map(s => s.server))].slice(0, 2).forEach(sv => {
    qs.push([`server="${sv}" && header="subscription-userinfo"`, `Server=${sv} 的订阅端点`]);
  });
  if (ips.length) qs.push([`ip="${ips[0]}"`, '节点域名解析 IP 的资产']);
  qs.push([`header="subscription-userinfo" && country="SG"`, '新加坡订阅端点(按需改国家)']);
  P.push(queryBlock(qs));
  P.push(`<div class="card"><div class="kv"><b>Quake response 精确搜(需登录)</b></div><code>response:"YToo_SS.yaml"</code><br><a href="${quakeLink('response:"YToo_SS.yaml"')}">→ Quake 搜文件名</a></div>`);
  P.push('<h2>📡 指纹汇总</h2>');
  P.push(`<div class="card">${servers.map(s => `<div class="kv">${esc(s.port)} → Server: <code>${esc(s.server)}</code></div>`).join('')}<div class="kv">文件名: <code>${esc(cdSeen || '未探测到')}</code></div><div class="kv">userinfo: <code>${esc(uiSeen ? parseUserinfo(uiSeen) : '未探测到')}</code></div></div>`);
  return page('probe ' + host, P.join(''));
}

async function doSubcheck(url) {
  const r = await req({ url: url, headers: { 'User-Agent': 'clash-verge/v1.7.7' }, timeout: 20000 });
  const hh = {};
  Object.keys(r.headers).forEach(k => { hh[k.toLowerCase()] = String(r.headers[k]); });
  const a = r.body ? analyzeBody(r.body) : { protos: {}, names: [], hit: false, wasB64: false, isClash: false, isSingbox: false };
  const H = [];
  H.push(`<div class="card"><div class="kv"><b>请求</b></div><div class="kv mono">${esc(url)}</div><div class="kv">状态: <code>${esc(r.status)}</code>${a.hit ? ' <span class="hit">⚠️ 命中 Ytoo 特征!</span>' : ''}</div></div>`);
  H.push(`<div class="card"><div class="kv"><b>关键响应头</b></div>`);
  [['content-disposition', '文件名'], ['subscription-userinfo', '流量配额'], ['profile-web-page-url', '机场主页'], ['content-type', '类型'], ['server', 'Server']].forEach(([k, lab]) => {
    if (hh[k]) H.push(`<div class="kv">${lab}: <code>${esc(k === 'subscription-userinfo' ? parseUserinfo(hh[k]) : hh[k])}</code></div>`);
  });
  H.push('</div>');
  const pt = Object.entries(a.protos).map(([k, v]) => `${k}×${v}`).join(' · ');
  if (pt) H.push(`<div class="card"><div class="kv"><b>协议统计</b> ${a.wasB64 ? '(base64 已解码)' : ''} ${a.isClash ? '· clash yaml' : ''}${a.isSingbox ? '· sing-box' : ''}</div><div class="kv"><code>${esc(pt)}</code></div></div>`);
  if (a.names.length) H.push(`<div class="card"><div class="kv"><b>节点名样本 (前${a.names.length})</b></div>${a.names.map(n => `<div class="kv">${a.hit && FEATURES.test(n) ? '<span class=hit>' : ''}${esc(n)}${a.hit && FEATURES.test(n) ? '</span>' : ''}</div>`).join('')}</div>`);
  if (!r.body) H.push(`<div class="card"><div class="kv"><span class="hit">无响应体 — 端点死/路径错</span></div></div>`);
  H.push(`<div class="small">下一步: 把响应头里的域名/文件名特征喂给 FOFA — <a href="https://fofa.info/result?qbase64=${encodeURIComponent(b64e('header="subscription-userinfo"'))}">搜全部订阅端点</a></div>`);
  return page('subcheck', H.join(''));
}

async function doCrt(q) {
  const c = await req({ url: `https://crt.sh/?q=${encodeURIComponent(q)}&output=json`, timeout: 25000 });
  let doms = [];
  try { doms = [...new Set(JSON.parse(c.body).flatMap(x => String(x.name_value).split('\n')))]; } catch (e) {}
  const H = doms.length
    ? doms.slice(0, 40).map(d => `<div class="kv mono">${esc(d)}</div>`).join('') + '<h2>🎯 批量检索</h2>' + queryBlock(doms.slice(0, 5).map(d => [`domain="${d}"`, d]))
    : `<div class="card">crt.sh 无结果/超时 — <a href="https://crt.sh/?q=${encodeURIComponent(q)}">网页版</a> · <a href="https://censys.io/search?q=${encodeURIComponent(q)}">Censys</a></div>`;
  return page('crt ' + q, H);
}

async function doWatch(notifyOnly) {
  const r = await req({ url: WATCH + 'YToo_SS.yaml', timeout: 15000 });
  const alive = r.status === '200' && r.body;
  const hh = {};
  Object.keys(r.headers).forEach(k => { hh[k.toLowerCase()] = String(r.headers[k]); });
  if (notifyOnly) {
    if (alive) { $persistentStore.write('ytoo_alive', String(Date.now())); $notify('🎉 YToo 服务器复活!', r.body.length + ' bytes', '快去 Loon 更新订阅'); }
    return;
  }
  const H = `<div class="card"><div class="kv">探测 <code>${esc(WATCH)}YToo_SS.yaml</code></div><div class="kv">状态: <code>${esc(r.status)}</code> ${alive ? '<span class="hit">✅ 活了!! 文件已可拉取</span>' : '— 仍无响应'}</div>${hh['content-disposition'] ? `<div class="kv">文件名: <code>${esc(hh['content-disposition'])}</code></div>` : ''}${r.body ? `<div class="card"><pre style="white-space:pre-wrap;margin:0"><code>${esc(r.body.slice(0, 800))}</code></pre></div>` : ''}</div>`;
  return page('watch', H);
}

async function home() {
  return page('home', `
<h2>① 节点服务器指纹</h2>
<div class="card"><div class="small">Loon → 服务器 → 点开 Ytoo 的任一节点, 抄下 server(域名或IP)和 port</div>
<form action="/probe" method="get"><input name="host" placeholder="server, 例: 1.2.3.4 或 s1.xxxx.com"><input name="port" placeholder="port, 例: 8443"><button type="submit">开挖 → FOFA/Quake 检索串</button></form></div>
<h2>② 订阅端点验证</h2>
<div class="card"><div class="small">在 FOFA/Quake 找到候选订阅 URL 后, 粘贴到这里验证是不是这家机场</div>
<form action="/subcheck" method="get"><input name="url" placeholder="https://xxxx/api/v1/client/subscribe?token=..."><button type="submit">验证 → 响应头+节点名</button></form></div>
<h2>③ 证书透明度域名族</h2>
<div class="card"><form action="/crt" method="get"><input name="q" placeholder="机场域名, 例: xxxx.com → 挖全部子域"><button type="submit">查 crt.sh</button></form></div>
<h2>④ 复活监视</h2>
<div class="card"><div class="kv">监视目标: <code>${esc(WATCH)}</code></div><a href="/watch"><button type="button">手动查一次 43.134.88.243:8080</button></a><div class="small">插件自带 cron 每 30 分钟自动查, 复活会弹通知</div></div>
<h2>使用流程</h2>
<div class="card small">1. Loon 点开 Ytoo 节点抄 server:port → ① 出检索串 → 2. 点 FOFA/Quake 链接搜 → 3. 找到可疑订阅 URL → ② 验证 → 4. 命中后把订阅 URL 填进 Loon, 删掉死掉的 xmf1 短链</div>`);
}

(async () => {
  try {
    const u = new URL($request.url);
    const p = u.pathname.replace(/\/+$/, '') || '/';
    let html;
    if (p === '/probe') html = await doProbe(u.searchParams.get('host') || '', u.searchParams.get('port') || '443');
    else if (p === '/subcheck') html = await doSubcheck(u.searchParams.get('url') || '');
    else if (p === '/crt') html = await doCrt(u.searchParams.get('q') || '');
    else if (p === '/watch') html = await doWatch(false);
    else html = await home();
    const headers = { 'Content-Type': 'text/html; charset=utf-8' };
    $done({ response: { status: 200, headers, body: html }, status: 200, headers, body: html });
  } catch (e) {
    const html = page('error', `<div class="card"><span class="hit">脚本错误:</span> <code>${esc(e && e.message || e)}</code></div>`);
    $done({ response: { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' }, body: html } });
  }
})();
