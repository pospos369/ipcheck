// 将文件顶部改为ESM导入方式
import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';

const app = express();

// --- 基础配置 ---
app.set('trust proxy', true); // 如果有受信代理（如 Nginx/Cloudflare），建议保留

const PORT = process.env.SERVER_PORT || 3000;
const TRUSTED_ORIGIN = process.env.TRUSTED_ORIGIN || `http://localhost:${PORT}`;

const PAGE_TITLE = process.env.PAGE_TITLE || 'IP查询';
const COPYRIGHT = process.env.COPYRIGHT || 'IP查询服务';

// HTML 转义，防止 XSS
const escapeHTML = (val = '') =>
  String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

// 常见爬虫User-Agent列表（全部小写）
const BOT_AGENTS = [
  'bot', 'spider', 'crawler', 'scanner',
  'python-requests', 'go-http-client', 'java', 'okhttp',
  'qihoobot', 'baiduspider', 'googlebot', 'googlebot-mobile',
  'googlebot-image', 'mediapartners-google', 'adsbot-google',
  'feedfetcher-google', 'yahoo! slurp', 'yahoo! slurp china',
  'youdaobot', 'sosospider', 'sogou spider', 'sogou web spider',
  'msnbot', 'ia_archiver', 'tomato bot'
];

// 内存缓存（临时封禁）
const BLOCKED_IPS = new Map();
const BLOCK_TIME = 60 * 1000; // 60s

// --- 访问日志 ---
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(
      `${new Date().toISOString()} - ${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`
    );
  });
  next();
});

// --- IP 提取 ---
const extractIPv4ForDisplay = (ip = '') => {
  if (ip.startsWith('::ffff:')) return ip.split(':').pop();
  return ip;
};

// --- 主页 ---
app.get('/', async (req, res) => {
  // 每次请求生成随机 nonce
  const nonce = crypto.randomBytes(16).toString('base64');

  // 设置 CSP 响应头，允许本域脚本和带 nonce 的脚本执行
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');

  // 获取来源 IP
  const rawIP = req.ip || '';
  const clientIP = extractIPv4ForDisplay(rawIP) || '未知IP';

  // 封禁检查
  const until = BLOCKED_IPS.get(clientIP);
  if (until && Date.now() < until) {
    return res.status(403).send('访问被拒绝');
  }

  // UA/Referer 检查
  const userAgentRaw = req.headers['user-agent'] || '';
  const userAgent = userAgentRaw.toLowerCase();
  const isBot = BOT_AGENTS.some(agent => userAgent.includes(agent));

  const referer = req.headers.referer || '';
  let isSuspiciousReferer = false;
  if (referer) {
    try {
      const refURL = new URL(referer);
      const trustedURL = new URL(TRUSTED_ORIGIN);
      isSuspiciousReferer = refURL.hostname !== trustedURL.hostname;
    } catch {
      isSuspiciousReferer = true;
    }
  }

  if (isBot || isSuspiciousReferer) {
    BLOCKED_IPS.set(clientIP, Date.now() + BLOCK_TIME);
    return res.status(403).send('访问被拒绝');
  }

  // curl 输出
  const isCurl = userAgent.includes('curl');
  if (isCurl) {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.set('Cache-Control', 'max-age=60');
    return res.send(clientIP);
  }

  // 调用百度开放数据平台
  const geoUrl = `http://opendata.baidu.com/api.php?query=${encodeURIComponent(
    clientIP
  )}&co=&resource_id=6006&oe=utf8`;

  let geoData = {};
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const geoResponse = await fetch(geoUrl, { signal: controller.signal });
    geoData = await geoResponse.json().catch(() => ({}));
  } catch (err) {
    console.error('Geo API 请求失败:', err);
    geoData = {};
  } finally {
    clearTimeout(timeout);
  }

  // 处理地理信息
  const formatLocation = () => {
    try {
      if (geoData.status !== '0' || !geoData.data?.[0]?.location) return '未知';
      return String(geoData.data[0].location).split(' ').slice(0, -1).join(' ') || '未知';
    } catch {
      return '未知';
    }
  };
  const formatISP = () => {
    try {
      if (geoData.status !== '0' || !geoData.data?.[0]?.location) return '未知';
      const locationStr = String(geoData.data[0].location);
      return locationStr.split(' ').pop() || '未知';
    } catch {
      return '未知';
    }
  };

  const location = formatLocation();
  const isp = formatISP();
  const asn = '未知';

  // 使用受信主机作为 curl 目标
  const curlTarget = TRUSTED_ORIGIN;

  // HTML 输出
  const html = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <title>${escapeHTML(PAGE_TITLE)}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      :root {
        --primary-color: #3498db;
        --secondary-color: #2980b9;
        --bg-color: #f8f9fa;
        --card-bg: #ffffff;
        --text-color: #333333;
        --border-color: #e0e0e0;
      }
      body {
        font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
        background-color: var(--bg-color);
        color: var(--text-color);
        line-height: 1.6;
        margin: 0;
        padding: 20px;
      }
      .container { max-width: 800px; margin: 0 auto; padding: 20px; }
      .header { text-align: center; margin-bottom: 30px; }
      .header h1 { color: var(--primary-color); margin-bottom: 10px; }
      .ip-card {
        background: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        padding: 25px; margin-bottom: 20px;
      }
      .info-row { display: flex; padding: 10px 0; border-bottom: 1px solid var(--border-color); }
      .info-row:last-child { border-bottom: none; }
      .info-label { font-weight: bold; min-width: 120px; color: var(--secondary-color); }
      .footer { text-align: center; margin-top: 30px; color: #777; font-size: 0.9em; }
      @media (max-width: 600px) {
        .info-row { flex-direction: column; }
        .info-label { margin-bottom: 5px; }
      }
      code {
        background-color: #f0f0f0; padding: 2px 5px; border-radius: 3px; border: 2px solid #ddd; color: #111;
      }
      button {
        margin-left: 5px; padding: 2px 8px; background: #063250; color: #fff; border: none; border-radius: 3px; cursor: pointer;
      }
      .ok { display:none; margin-left:10px; color:#28a745; }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1>${escapeHTML(PAGE_TITLE)}</h1>
        <p>您的网络连接信息如下</p>
      </div>

      <div class="ip-card">
        <div class="info-row">
          <span class="info-label">IP地址</span>
          <span>${escapeHTML(clientIP)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">地理位置</span>
          <span>${escapeHTML(location)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">网络运营商</span>
          <span>${escapeHTML(isp)} (AS${escapeHTML(asn)})</span>
        </div>
        <div class="info-row">
          <span class="info-label">User-Agent</span>
          <span style="word-break: break-all;">${escapeHTML(userAgentRaw)}</span>
        </div>
      </div>

      <div class="footer">
        <p>使用命令行工具获取纯文本IP:
          <code id="curlCommand">curl -L ${escapeHTML(curlTarget)}</code>
          <button id="copyBtn">复制</button>
          <span id="copyTips" class="ok">✓ 已复制</span>
        </p>
        <p>© ${new Date().getFullYear()} ${escapeHTML(COPYRIGHT)}</p>
      </div>
    </div>
    <script nonce="${nonce}">
      (function () {
        var btn = document.getElementById('copyBtn');
        var tips = document.getElementById('copyTips');
        var cmd = document.getElementById('curlCommand').textContent;
        btn.addEventListener('click', function () {
          navigator.clipboard.writeText(cmd).then(function () {
            tips.style.display = 'inline';
            setTimeout(function () { tips.style.display = 'none'; }, 2000);
          }).catch(function (err) {
            console.error('复制失败:', err);
          });
        });
      })();
    </script>
  </body>
  </html>
  `;

  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('Cache-Control', 'no-store');
  return res.send(html);
});

app.listen(PORT, () => {
  console.log(`服务器运行在 ${TRUSTED_ORIGIN}`);
});
