const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// 配置项
const CONFIG = {
  // 要守护的目标文件
  targetFile: path.resolve(__dirname, 'example.js'),
  // 日志文件路径
  logFile: path.resolve(__dirname, 'daemon.log'),
  // 崩溃后重启延迟（毫秒）
  restartDelay: 2000,
  // 最大重启次数（防止无限重启）
  maxRestartTimes: 10,
  // 当前重启计数
  restartCount: 0
};

// 日志记录函数
function log(message) {
  const time = new Date().toISOString();
  const logContent = `[${time}] ${message}\n`;
  // 追加写入日志文件
  fs.appendFileSync(CONFIG.logFile, logContent);
  // 同时输出到控制台
  console.log(logContent.trim());
}

// 启动目标进程的核心函数
function startProcess() {
  if (CONFIG.restartCount >= CONFIG.maxRestartTimes) {
    log(`⚠️  达到最大重启次数(${CONFIG.maxRestartTimes})，停止守护`);
    return;
  }

  log(`🚀 启动目标文件: ${CONFIG.targetFile}`);
  // 启动 example.js 子进程
  const child = spawn('node', [CONFIG.targetFile], {
    stdio: 'inherit' // 继承父进程的输入输出（方便看到 example.js 的日志）
  });

  // 进程退出监听
  child.on('exit', (code, signal) => {
    CONFIG.restartCount++;
    if (code === 0) {
      log(`✅ 进程正常退出 (代码: ${code})`);
    } else {
      log(`❌ 进程异常退出 (代码: ${code}, 信号: ${signal})，${CONFIG.restartDelay/1000} 秒后重启（第 ${CONFIG.restartCount} 次）`);
      // 延迟重启
      setTimeout(startProcess, CONFIG.restartDelay);
    }
  });

  // 进程出错监听
  child.on('error', (err) => {
    log(`❌ 进程启动失败: ${err.message}`);
    CONFIG.restartCount++;
    setTimeout(startProcess, CONFIG.restartDelay);
  });

  // 捕获父进程终止信号（比如 Ctrl+C）
  process.on('SIGINT', () => {
    log(`🛑 守护进程被终止，正在关闭子进程...`);
    child.kill('SIGINT');
    process.exit(0);
  });
}

// 检查目标文件是否存在
if (!fs.existsSync(CONFIG.targetFile)) {
  log(`❌ 目标文件不存在: ${CONFIG.targetFile}`);
  process.exit(1);
}

// 启动守护
startProcess();