// 将文件顶部改为ESM导入方式
import express from 'express';
import fetch from 'node-fetch';

const app = express();

// 添加访问日志中间件
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`);
  });
  next();
});

// 从环境变量获取配置，设置默认值
const PORT = process.env.SERVER_PORT || 3000;
const PAGE_TITLE = process.env.PAGE_TITLE || 'IP查询';
const COPYRIGHT = process.env.PAGE_TITLE || ' IP查询服务';

// 常见爬虫User-Agent列表
const BOT_AGENTS = [
  'bot', 'spider', 'crawler', 'scanner',
  'python-requests', 'go-http-client', 'java', 'okhttp',
  'qihoobot', 'baiduspider', 'googlebot', 'googlebot-mobile',
  'googlebot-image', 'mediapartners-google', 'adsbot-google',
  'feedfetcher-google', 'yahoo! slurp', 'yahoo! slurp china',
  'youdaobot', 'sosospider', 'sogou spider', 'sogou web spider',
  'msnbot', 'ia_archiver', 'tomato bot'
];

// 内存缓存
const BLOCKED_IPS = new Map();
const BLOCK_TIME = 60 * 1000;

app.get('/', async (req, res) => {
  const clientHost = req.get('x-forwarded-host') || req.get('host');
  // 获取并清理IP地址
  const getClientIP = () => {
    // 处理IPv4映射的IPv6地址格式 (::ffff:192.168.1.1)
    const extractIPv4 = (ip) => {
      if (ip.startsWith('::ffff:')) {
        return ip.split(':').pop(); // 提取IPv4部分
      }
      return ip; // 纯IPv6地址保持不变
    };

    // 1. 检查X-Forwarded-For头
    const xForwardedFor = req.headers['x-forwarded-for'];
    if (xForwardedFor) {
      const ips = xForwardedFor.split(',');
      for (const ip of ips) {
        const trimmedIp = ip.trim();
        // 如果是IPv4或IPv4映射的IPv6地址
        if (trimmedIp.includes('.') || trimmedIp.startsWith('::ffff:')) {
          return extractIPv4(trimmedIp);
        }
      }
    }

    // 2. 检查req.ip和connection.remoteAddress
    const possibleIPs = [
      req.ip,
      req.connection.remoteAddress,
      req.socket.remoteAddress,
      req.connection.socket?.remoteAddress
    ];

    for (const ip of possibleIPs) {
      if (ip && (ip.includes('.') || ip.startsWith('::ffff:'))) {
        return extractIPv4(ip);
      }
    }

    // 3. 回退方案 - 返回原始IP（可能是纯IPv6）
    return req.ip || req.connection.remoteAddress || '未知IP';
  };
  
  const clientIP = getClientIP();
  
  // 1. 检查是否在屏蔽名单中
  if (BLOCKED_IPS.has(clientIP) && Date.now() < BLOCKED_IPS.get(clientIP)) {
    return res.status(403).send('访问被拒绝');
  }

  // 2. 检查User-Agent
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const isBot = BOT_AGENTS.some(agent => userAgent.includes(agent));
  
  // 3. 检查Referer
  const referer = req.headers.referer || '';
  const isSuspiciousReferer = referer && !referer.includes(req.hostname);

  if (isBot || isSuspiciousReferer) {
    BLOCKED_IPS.set(clientIP, Date.now() + BLOCK_TIME);
    return res.status(403).send('访问被拒绝');
  }

  const isCurl = userAgent.includes('curl');
  if (isCurl) {
    res.set('Content-Type', 'text/plain');
    res.set('Cache-Control', 'max-age=60');
    return res.send(clientIP);
  }

  // 调用百度开放数据平台获取地理位置信息
  const geoUrl = `http://opendata.baidu.com/api.php?query=${clientIP}&co=&resource_id=6006&oe=utf8`;
  const geoResponse = await fetch(geoUrl);
  const geoData = await geoResponse.json();

  // 处理地理位置数据
  const formatLocation = () => {
    if (geoData.status !== "0" || !geoData.data?.[0]?.location) return '未知';
    // 移除运营商信息（如"广东省广州市 移动" → "广东省广州市"）
    return geoData.data[0].location.split(' ').slice(0, -1).join(' ');
  };

  const formatISP = () => {
    if (geoData.status !== "0" || !geoData.data?.[0]?.location) return '未知';
    const locationStr = geoData.data[0].location;
    // 从字符串中提取运营商信息，如"广东省广州市 移动"中的"移动"
    return locationStr.split(' ').pop() || '未知';
  };

  const location = formatLocation();
  const isp = formatISP();
  const asn = '未知'; // 百度接口不提供ASN信息

  // 修改HTML中的title部分
  const html = `
  <!DOCTYPE html>
  <html>
  <head>
    <title>${PAGE_TITLE}</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
      .container {
        max-width: 800px;
        margin: 0 auto;
        padding: 20px;
      }
      .header {
        text-align: center;
        margin-bottom: 30px;
      }
      .header h1 {
        color: var(--primary-color);
        margin-bottom: 10px;
      }
      .ip-card {
        background: var(--card-bg);
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        padding: 25px;
        margin-bottom: 20px;
      }
      .info-row {
        display: flex;
        padding: 10px 0;
        border-bottom: 1px solid var(--border-color);
      }
      .info-row:last-child {
        border-bottom: none;
      }
      .info-label {
        font-weight: bold;
        min-width: 120px;
        color: var(--secondary-color);
      }
      .footer {
        text-align: center;
        margin-top: 30px;
        color: #777;
        font-size: 0.9em;
      }
      @media (max-width: 600px) {
        .info-row {
          flex-direction: column;
        }
        .info-label {
          margin-bottom: 5px;
        }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1>${PAGE_TITLE}</h1>
        <p>您的网络连接信息如下</p>
      </div>
      
      <div class="ip-card">
        <div class="info-row">
          <span class="info-label">IP地址</span>
          <span>${clientIP}</span>
        </div>
        <div class="info-row">
          <span class="info-label">地理位置</span>
          <span>${location}</span>
        </div>
        <div class="info-row">
          <span class="info-label">网络运营商</span>
          <span>${isp} (AS${asn})</span>
        </div>
        <div class="info-row">
          <span class="info-label">User-Agent</span>
          <span style="word-break: break-all;">${userAgent}</span>
        </div>
      </div>
      
      <div class="footer">
        <p>使用命令行工具获取纯文本IP: 
          <code id="curlCommand" style="background-color: #f0f0f0; padding: 2px 5px; border-radius: 3px; border: 2px solid #ddd; color:rgb(17, 16, 17);">curl -L ${clientHost}</code>
          <button onclick="copyCurlCommand()" style="margin-left: 5px; padding: 2px 8px; background:rgb(6, 50, 80); color: white; border: none; border-radius: 3px; cursor: pointer;">复制</button>
          <span id="copyTips" style="display:none; margin-left:10px; color:#28a745;">✓ 已复制</span>
        </p>
        <p>© ${new Date().getFullYear()} ${COPYRIGHT}</p>
      </div>
    </div>
    <script>
      function copyCurlCommand() {
        const curlCommand = document.getElementById('curlCommand').textContent;
        const tips = document.getElementById('copyTips');
        
        navigator.clipboard.writeText(curlCommand).then(() => {
          tips.style.display = 'inline';
          setTimeout(() => tips.style.display = 'none', 2000);
        }).catch(err => {
          console.error('复制失败:', err);
        });
      }
    </script>
  </body>
  </html>
  `;

  res.set('Content-Type', 'text/html');
  res.send(html);
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
