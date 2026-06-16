const { Server } = require('ssh2');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const axios = require('axios');

// ===================== 全局异常捕获（核心防退出） =====================
process.on('uncaughtException', (err) => {
  console.error('[FATAL] 未捕获异常，服务继续运行:', err.message, err.stack);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] 未处理Promise拒绝，服务继续运行:', reason?.message || reason);
});

// ===================== 核心配置 =====================
const hostKey = fs.readFileSync(path.join(__dirname, 'host_rsa.key'));
const asciiFrames = fs.readFileSync(path.join(__dirname, 'badapple_ascii.txt'), 'utf8')
  .split('---FRAME_SEPARATOR---\n')
  .filter(f => f.trim().length > 0);

const sshPort = parseInt(process.env.SSH_PORT, 10) || 22;
const webPort = 763;
const MAX_IP_CACHE = 500;       // IP地区缓存最大数量，防内存溢出
const CLIENT_TIMEOUT = 120000;  // 单连接最大超时 2分钟

// 日志文件
const attackLogFile = path.join(__dirname, 'attack_logs.txt');
const connectionLogFile = path.join(__dirname, 'connection_logs.txt');

// 统计变量
let attackCounter = 0;
let totalDataTransferred = 0;
let activeConnections = new Set();
let accessLog = [];

// IP地区缓存（仅存中文名称）+ 缓存淘汰
const ipLocationCache = {};
const IP_LOCATION_API = 'https://ipip.yxpil.com/classify/';

// ===================== 工具函数 =====================
function getTimestamp() {
  return new Date().toISOString();
}

function getClientIP(client) {
  try {
    return client?._sock?.remoteAddress || 'unknown';
  } catch (e) {
    return 'unknown';
  }
}

// 安全文件追加写入
function safeAppendFile(filePath, content) {
  try {
    fs.appendFileSync(filePath, content);
  } catch (e) {
    console.error(`[LOG ERROR] 写入日志失败 ${filePath}:`, e.message);
  }
}

// ===================== IP地区查询（加强容错+缓存淘汰） =====================
async function getIPCountryName(ip) {
  if (!ip || ip === 'unknown' || ip === '127.0.0.1'
    || ip.startsWith('192.168.') || ip.startsWith('10.')
    || ip.startsWith('172.')) {
    return '本地IP';
  }

  if (ipLocationCache[ip]) {
    return ipLocationCache[ip];
  }

  // 缓存淘汰：超过上限清空一半
  const keys = Object.keys(ipLocationCache);
  if (keys.length >= MAX_IP_CACHE) {
    keys.slice(0, Math.floor(MAX_IP_CACHE / 2)).forEach(k => delete ipLocationCache[k]);
  }

  try {
    const response = await axios.get(`${IP_LOCATION_API}${ip}`, {
      timeout: 3000,
      headers: { 'User-Agent': 'SSH-Honeypot/1.0' }
    });
    const countryName = response.data.classification?.countryName || '未知地区';
    ipLocationCache[ip] = countryName;
    return countryName;
  } catch (error) {
    console.warn(`[!] 查询IP ${ip} 地区失败：${error.message}`);
    ipLocationCache[ip] = '未知地区';
    return '未知地区';
  }
}

// ===================== 日志记录（全加 try/catch） =====================
async function logAttack(ip, username, method, details = '') {
  try {
    attackCounter++;
    const countryName = await getIPCountryName(ip);
    const logEntry = {
      timestamp: getTimestamp(),
      attack_id: `ATTACK_${attackCounter.toString().padStart(6, '0')}`,
      source_ip: ip,
      countryName: countryName,
      username: username,
      auth_method: method,
      success: true,
      attack_type: 'ssh_brute_force',
      details: details,
      user_agent: 'ssh_client',
      target_port: sshPort
    };
    safeAppendFile(attackLogFile, JSON.stringify(logEntry) + '\n');
    accessLog.push({ type: 'attack', ...logEntry });
    console.log(`[ATTACK] ${logEntry.attack_id} from ${ip} (${countryName}) user=${username} method=${method}`);
  } catch (e) {
    console.error('[logAttack] 日志异常:', e.message);
  }
}

async function logConnection(ip, connectionId, event, details = '') {
  try {
    const countryName = await getIPCountryName(ip);
    const logEntry = {
      timestamp: getTimestamp(),
      connection_id: connectionId,
      source_ip: ip,
      countryName: countryName,
      event: event,
      details: details,
      active_connections: activeConnections.size
    };
    safeAppendFile(connectionLogFile, JSON.stringify(logEntry) + '\n');
    accessLog.push({ type: 'connection', ...logEntry });
    console.log(`[CONNECTION] ${connectionId} ${event} from ${ip} (${countryName})`);
  } catch (e) {
    console.error('[logConnection] 日志异常:', e.message);
  }
}

// ===================== SSH 服务配置 =====================
const serverConfig = {
  hostKeys: [hostKey],
  banner: '🎬 SSH ASCII Art Honeypot - Bad Apple Animation 🎬\n',
  ident: 'SSH-2.0-OpenSSH_8.9p1',
  algorithms: {
    kex: ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'],
    cipher: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm', 'aes256-gcm', 'aes128-cbc', 'aes256-cbc', '3des-cbc'],
    hmac: ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1', 'hmac-md5'],
    compress: ['none', 'zlib@openssh.com', 'zlib']
  }
};

// ===================== 动画播放（定时器安全销毁 + 流状态校验） =====================
function playASCIIAnimation(stream, connectionId, clientIP, onProgress) {
  let frameIndex = 0;
  let transferredBytes = 0;
  const totalFrames = asciiFrames.length;
  const startTime = Date.now();
  let animInterval = null;
  let isStreamDestroyed = false;

  console.log(`[*] Starting ASCII animation for ${connectionId}, total frames: ${totalFrames}`);
  logConnection(clientIP, connectionId, 'ascii_animation_started', `frames=${totalFrames}`).catch(() => { });

  // 标记流已销毁
  const markDestroy = () => {
    isStreamDestroyed = true;
    if (animInterval) {
      clearInterval(animInterval);
      animInterval = null;
    }
  };

  // 监听流关闭/错误，强制停定时器
  stream.on('close', markDestroy);
  stream.on('end', markDestroy);
  stream.on('error', (err) => {
    console.error(`[STREAM ERR] ${connectionId} stream error:`, err.message);
    markDestroy();
  });

  // 清屏 + 隐藏光标
  if (!isStreamDestroyed) {
    stream.write('\x1b[2J\x1b[H\x1b[?25l');
  }

  animInterval = setInterval(() => {
    if (isStreamDestroyed || !stream.writable) {
      clearInterval(animInterval);
      animInterval = null;
      return;
    }

    if (frameIndex >= totalFrames) {
      clearInterval(animInterval);
      animInterval = null;
      const duration = Date.now() - startTime;

      stream.write('\x1b[?25h\x1b[2J\x1b[H');
      stream.write('\n\n🎬 ASCII动画播放完成！感谢观看！bilibili：https://space.bilibili.com/515222887 more info https://yxp.hk/🎬\n');
      stream.write('🌟 Thanks for visiting the SSH ASCII Art Honeypot! 🌟\n');

      console.log(`[*] ASCII animation completed for ${connectionId}, duration: ${duration}ms`);
      logConnection(clientIP, connectionId, 'ascii_animation_completed', `duration=${duration}ms`).catch(() => { });

      setTimeout(() => {
        if (stream.writable) {
          stream.exit(0);
          stream.end();
        }
      }, 3000);
      return;
    }

    const frame = asciiFrames[frameIndex];
    const normalizedFrame = frame.replace(/\r?\n/g, '\r\n');
    const frameData = `\x1b[2J\x1b[H${normalizedFrame}\r\n\x1b[38;2;220;20;60mFrame: ${frameIndex + 1}/${totalFrames}\r\n`;

    if (stream.writable) {
      stream.write(frameData);
    }

    transferredBytes += Buffer.byteLength(frameData);
    onProgress(transferredBytes);

    if (frameIndex % 100 === 0) {
      const progress = Math.floor((frameIndex / totalFrames) * 100);
      console.log(`[*] Animation progress for ${connectionId}: ${progress}% (${frameIndex}/${totalFrames})`);
      logConnection(clientIP, connectionId, 'animation_progress', `${progress}%`).catch(() => { });
    }

    frameIndex++;
  }, 100);
}

// 启动交互式 shell
function startShell(stream, connectionId, clientIP, onTransferred) {
  console.log(`[*] Shell session started for ${connectionId}`);
  logConnection(clientIP, connectionId, 'shell_session_started').catch(() => { });

  // 流异常监听
  stream.on('error', (err) => {
    console.error(`[SHELL STREAM ERR] ${connectionId}:`, err.message);
  });

  const header = '\x1b[38;2;220;20;60m╔══════════════════════════════════════════════════════════════════════╗\n' +
    '║                                                                      ║\n' +
    '║  🎬 SSH ASCII Art Honeypot - Bad Apple Animation 🎬               ║\n' +
    '║                                                                      ║\n' +
    '║  🍎 Now Playing: Bad Apple!! ASCII Art Animation                     ║\n' +
    '║  📺 Format: 80x30 ASCII Art, 10 FPS                                ║\n' +
    '║                                                                      ║\n' +
    '╚══════════════════════════════════════════════════════════════════════╝\n\n' +
    '🎬 Welcome! Enjoy the Bad Apple ASCII art animation! 🎬\n\n' +
    'Attacked for long? Have a break. Playing Bad Apple...\n' +
    '攻击了很久你累了吧 听个音乐\n\n';

  if (stream.writable) stream.write(header);
  playASCIIAnimation(stream, connectionId, clientIP, onTransferred);
}

// 显示统计信息
function showStats() {
  try {
    console.log('\n' + '='.repeat(60));
    console.log('🎬 SSH ASCII ART HONEYPOT - SYSTEM STATISTICS 🎬');
    console.log('='.repeat(60));
    console.log(`📊 Total attacks: ${attackCounter}`);
    console.log(`🔗 Active connections: ${activeConnections.size}`);
    console.log(`📡 Data transferred: ${(totalDataTransferred / 1024).toFixed(2)} KB`);
    console.log(`🎬 Animation frames: ${asciiFrames.length}`);
    console.log(`📺 Duration: ${(asciiFrames.length / 10).toFixed(1)} seconds @ 10 FPS`);
    console.log(`🌍 IP缓存数量: ${Object.keys(ipLocationCache).length}`);
    console.log('='.repeat(60) + '\n');
  } catch (e) {
    console.error('[showStats] 统计输出异常:', e.message);
  }
}

// ===================== SSH 主服务逻辑 =====================
const sshServer = new Server(serverConfig, async (client) => {
  const clientIP = getClientIP(client);
  const connectionId = `CONN_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  let connTimeout = null;

  // 全局连接超时，防止僵死连接
  connTimeout = setTimeout(() => {
    console.log(`[TIMEOUT] ${connectionId} 连接超时，主动断开`);
    client.end();
  }, CLIENT_TIMEOUT);

  activeConnections.add(connectionId);
  getIPCountryName(clientIP).then(countryName => {
    console.log(`[+] New connection from ${clientIP} (${countryName}) (ID: ${connectionId})`);
  }).catch(() => { });
  logConnection(clientIP, connectionId, 'connection_established').catch(() => { });

  let bytesTransferred = 0;

  // 客户端顶层错误监听
  client.on('error', (err) => {
    console.error(`[CLIENT ERR] ${connectionId}:`, err.message);
  });

  client
    .on('request', (accept, reject, name) => {
      try {
        if (name === 'keepalive@openssh.com') {
          accept && accept();
          return;
        }
        reject && reject();
      } catch (e) { }
    })
    .on('authentication', async (ctx) => {
      try {
        console.log(`[*] Auth attempt from ${clientIP}: user=${ctx.username} method=${ctx.method}`);
        await logAttack(clientIP, ctx.username, ctx.method, `attempt_from_${clientIP}`);
        ctx.accept();
      } catch (e) {
        ctx.reject && ctx.reject();
      }
    })
    .on('ready', async () => {
      try {
        console.log(`[+] Client ${connectionId} authenticated successfully`);
        await logConnection(clientIP, connectionId, 'authentication_success');

        client.on('session', (accept) => {
          const session = accept();
          session.on('error', (err) => console.error(`[SESSION ERR] ${connectionId}:`, err.message));
          session.on('pty', (acceptPty) => acceptPty && acceptPty());
          session.on('env', (acceptEnv) => acceptEnv && acceptEnv());
          session.on('window-change', (acceptWin) => acceptWin && acceptWin());
          session.on('signal', (acceptSignal) => acceptSignal && acceptSignal());

          session.on('exec', (acceptExec) => {
            const stream = acceptExec();
            stream.write('Interactive shell only. Starting Bad Apple...\n');
            startShell(stream, connectionId, clientIP, (transferred) => { bytesTransferred = transferred; });
          });

          session.on('shell', (acceptShell) => {
            const stream = acceptShell();
            startShell(stream, connectionId, clientIP, (transferred) => { bytesTransferred = transferred; });
          });
        });
      } catch (e) {
        console.error(`[READY ERR] ${connectionId}:`, e.message);
      }
    })
    .on('end', async () => {
      // 清理超时定时器
      if (connTimeout) {
        clearTimeout(connTimeout);
        connTimeout = null;
      }
      activeConnections.delete(connectionId);
      console.log(`[*] Client ${connectionId} disconnected`);
      await logConnection(clientIP, connectionId, 'client_disconnected').catch(() => { });

      if (bytesTransferred > 0) {
        totalDataTransferred += bytesTransferred;
        console.log(`[STATS] Total data transferred: ${totalDataTransferred} bytes, Active connections: ${activeConnections.size}`);
      }
    });
});

// SSH 服务全局错误
sshServer.on('error', (err) => {
  console.error('[SSH SERVER FATAL ERR]', err.message, err.stack);
});

// ===================== Web 可视化服务 =====================
const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/logs/stats', (req, res) => {
  try {
    const authMethodStats = {};
    const ipStats = {};
    const countryStats = {};
    const timelineData = [];

    accessLog.slice(-100).forEach(log => {
      timelineData.push({
        time: log.timestamp,
        type: log.type,
        ip: log.source_ip,
        country: log.countryName || '未知地区',
        event: log.event || log.auth_method || 'unknown',
        id: log.attack_id || log.connection_id
      });

      if (log.type === 'attack' && log.auth_method) {
        authMethodStats[log.auth_method] = (authMethodStats[log.auth_method] || 0) + 1;
      }
      if (log.source_ip && log.source_ip !== 'unknown') {
        ipStats[log.source_ip] = (ipStats[log.source_ip] || 0) + 1;
      }
      const countryName = log.countryName || '未知地区';
      countryStats[countryName] = (countryStats[countryName] || 0) + 1;
    });

    const pieData = Object.entries(authMethodStats).map(([name, value]) => ({ name, value }));
    const ipPieData = Object.entries(ipStats).map(([name, value]) => ({ name, value }));
    const countryPieData = Object.entries(countryStats).map(([name, value]) => ({ name, value }));

    res.json({
      code: 200,
      data: {
        pie: pieData.length > 0 ? pieData : [{ name: '暂无数据', value: 1 }],
        ipPie: ipPieData.length > 0 ? ipPieData : [{ name: '暂无数据', value: 1 }],
        countryPie: countryPieData.length > 0 ? countryPieData : [{ name: '暂无数据', value: 1 }],
        timeline: timelineData.reverse(),
        totalAttacks: attackCounter,
        activeConnections: activeConnections.size,
        totalDataTransferred: (totalDataTransferred / 1024).toFixed(2),
        ipCacheCount: Object.keys(ipLocationCache).length
      }
    });
  } catch (err) {
    res.json({ code: 500, message: err.message });
  }
});

app.get('/', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>SSH蜜罐日志可视化（地区统计）</title>
  <script src="https://cdn.jsdelivr.net/npm/echarts/dist/echarts.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { padding: 20px; font-family: Arial, sans-serif; background: #f5f5f5; }
    .container { display: flex; gap: 20px; height: calc(100vh - 40px); }
    .left-panel { width: 40%; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .right-panel { width: 60%; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .chart-box { height: 30%; margin-bottom: 20px; }
    .timeline-box { height: 100%; overflow-y: auto; }
    .timeline-item { padding: 10px; border-bottom: 1px solid #eee; margin-bottom: 8px; border-radius: 4px; }
    .timeline-item.attack { background: #fff0f0; border-left: 4px solid #dc143c; }
    .timeline-item.connection { background: #f0f8ff; border-left: 4px solid #1e90ff; }
    .stats-header { margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #eee; }
    .stats-item { display: inline-block; margin-right: 20px; font-size: 14px; color: #333; }
    .stats-item strong { color: #dc143c; }
  </style>
</head>
<body>
  <div class="container">
    <div class="left-panel">
      <div class="stats-header">
        <h3>SSH蜜罐统计</h3>
        <div class="stats-item">总攻击数：<strong id="totalAttacks">0</strong></div>
        <div class="stats-item">活跃连接：<strong id="activeConnections">0</strong></div>
        <div class="stats-item">传输数据：<strong id="totalData">0</strong> KB</div>
        <div class="stats-item">IP缓存：<strong id="ipCacheCount">0</strong></div>
      </div>
      <div class="chart-box">
        <h4>认证方式占比</h4>
        <div id="authPieChart" style="width: 100%; height: 90%;"></div>
      </div>
      <div class="chart-box">
        <h4>攻击IP占比</h4>
        <div id="ipPieChart" style="width: 100%; height: 90%;"></div>
      </div>
      <div class="chart-box">
        <h4>地区分布占比</h4>
        <div id="countryPieChart" style="width: 100%; height: 90%;"></div>
      </div>
    </div>
    <div class="right-panel">
      <h3>实时日志时间轴（最近100条）</h3>
      <div class="timeline-box" id="timelineContainer"></div>
    </div>
  </div>

  <script>
    const authPieChart = echarts.init(document.getElementById('authPieChart'));
    const ipPieChart = echarts.init(document.getElementById('ipPieChart'));
    const countryPieChart = echarts.init(document.getElementById('countryPieChart'));

    const pieOption = {
      tooltip: { trigger: 'item' },
      legend: { orient: 'vertical', left: 'left', textStyle: { fontSize: 10 } },
      series: [{
        name: '占比',
        type: 'pie',
        radius: ['40%', '70%'],
        data: [],
        label: { show: true, formatter: '{b}: {c} ({d}%)', fontSize: 10 }
      }]
    };

    authPieChart.setOption(pieOption);
    ipPieChart.setOption(pieOption);
    countryPieChart.setOption(pieOption);

    function updateData() {
      fetch('/api/logs/stats')
        .then(res => res.json())
        .then(data => {
          if (data.code !== 200) return;
          document.getElementById('totalAttacks').textContent = data.data.totalAttacks;
          document.getElementById('activeConnections').textContent = data.data.activeConnections;
          document.getElementById('totalData').textContent = data.data.totalDataTransferred;
          document.getElementById('ipCacheCount').textContent = data.data.ipCacheCount;

          authPieChart.setOption({ series: [{ data: data.data.pie }] });
          ipPieChart.setOption({ series: [{ data: data.data.ipPie }] });
          countryPieChart.setOption({ series: [{ data: data.data.countryPie }] });

          const timelineContainer = document.getElementById('timelineContainer');
          timelineContainer.innerHTML = '';
          data.data.timeline.forEach(item => {
            const itemEl = document.createElement('div');
            itemEl.className = \`timeline-item \${item.type}\`;
            itemEl.innerHTML = \`
              <div><strong>时间：</strong>\${item.time}</div>
              <div><strong>类型：</strong>\${item.type === 'attack' ? '攻击' : '连接'}</div>
              <div><strong>IP：</strong>\${item.ip}</div>
              <div><strong>地区：</strong>\${item.country}</div>
              <div><strong>事件：</strong>\${item.event}</div>
              <div><strong>ID：</strong>\${item.id}</div>
            \`;
            timelineContainer.appendChild(itemEl);
          });
        })
        .catch(err => console.error('更新失败：', err));
    }

    updateData();
    setInterval(updateData, 2000);
    window.addEventListener('resize', () => {
      authPieChart.resize();
      ipPieChart.resize();
      countryPieChart.resize();
    });
  </script>
</body>
</html>
`;
  res.send(html);
});

// ===================== 启动服务 & 优雅退出 =====================
function startServer() {
  const initTime = getTimestamp();
  if (!fs.existsSync(attackLogFile)) {
    safeAppendFile(attackLogFile, `# SSH ASCII Art Honeypot Attack Logs\n# Started: ${initTime}\n\n`);
  }
  if (!fs.existsSync(connectionLogFile)) {
    safeAppendFile(connectionLogFile, `# SSH ASCII Art Honeypot Connection Logs\n# Started: ${initTime}\n\n`);
  }

  // 启动SSH
  sshServer.listen(sshPort, '0.0.0.0', () => {
    console.log(`🎬 SSH蜜罐启动：端口 ${sshPort}`);
    console.log(`🎬 动画帧数：${asciiFrames.length}，时长 ${(asciiFrames.length / 10).toFixed(1)}s`);
    console.log(`📝 日志文件：${attackLogFile} | ${connectionLogFile}`);
    setInterval(showStats, 30000);
  });

  // 启动Web
  app.listen(webPort, '0.0.0.0', () => {
    console.log(`🌐 Web可视化面板：http://0.0.0.0:${webPort}`);
    console.log(`🌍 IP地区查询接口：${IP_LOCATION_API}`);
  });

  // 优雅关闭
  process.on('SIGINT', () => {
    console.log('\n[!] 正在关闭蜜罐...');
    showStats();
    sshServer.close(() => {
      console.log('[✓] SSH蜜罐已停止');
      process.exit(0);
    });
  });
}

startServer();