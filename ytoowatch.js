/**
 * YToo 复活监视 — Loon cron 脚本 (每 30 分钟)
 * 43.134.88.243:8080 复活时弹通知
 */
const URLS = [
  'http://43.134.88.243:8080/YToo_SS.yaml',
  'http://43.134.88.243:8080/'
];

function req(opt) {
  return new Promise(res => {
    opt.timeout = opt.timeout || 15000;
    opt.policy = 'DIRECT';
    $httpClient.get(opt, (s, r, d) => res({ status: String(s || '0'), body: d == null ? '' : String(d), headers: r || {} }));
  });
}

(async () => {
  try {
    for (const u of URLS) {
      const r = await req({ url: u });
      if (r.status === '200' && r.body) {
        $persistentStore.write('ytoo_alive_at', String(Math.floor(Date.now() / 1000)));
        $notify('🎉 YToo 服务器复活了!', `${r.body.length} bytes · ${u.split('/').pop() || 'root'}`, '立刻去 Loon: 把 Ytoo 订阅更新一次, 或打开 ytoolab.local/watch 查看内容');
        break;
      }
    }
  } catch (e) {}
  $done({});
})();
