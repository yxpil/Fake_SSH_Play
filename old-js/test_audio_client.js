const net = require('net');
const { Client } = require('ssh2');

const conn = new Client();

conn.on('ready', () => {
  console.log('✅ 连接成功！');
  
  conn.shell((err, stream) => {
    if (err) throw err;
    
    let audioChunks = [];
    let totalChunks = 0;
    
    stream.on('close', () => {
      console.log('🔴 连接关闭');
      process.exit(0);
    }).on('data', (data) => {
      const text = data.toString();
      
      // 检测音频数据块
      if (text.includes('AUDIO_CHUNK:')) {
        const lines = text.split('\n');
        lines.forEach(line => {
          if (line.includes('AUDIO_CHUNK:')) {
            const match = line.match(/AUDIO_CHUNK:(\d+):([A-Za-z0-9+/=]+)/);
            if (match) {
              const chunkIndex = parseInt(match[1]);
              const base64Data = match[2];
              
              audioChunks[chunkIndex] = Buffer.from(base64Data, 'base64');
              totalChunks++;
              
              if (totalChunks % 50 === 0) {
                const progress = Math.floor((totalChunks * 512) / 639476 * 100);
                console.log(`🎵 收到音频数据: ${totalChunks} 块 (${progress}%)`);
              }
            }
          }
        });
      } else {
        // 显示其他消息
        process.stdout.write(text);
      }
    });
    
    // 30秒后结束
    setTimeout(() => {
      console.log('\n⏰ 测试完成，正在重组音频数据...');
      
      // 重组音频数据
      const audioBuffer = Buffer.concat(audioChunks.filter(chunk => chunk));
      console.log(`🎵 总共收到 ${audioBuffer.length} 字节音频数据`);
      
      if (audioBuffer.length > 0) {
        // 保存音频文件用于验证
        require('fs').writeFileSync('received_audio.mp3', audioBuffer);
        console.log('✅ 音频数据已保存为 received_audio.mp3');
      }
      
      stream.end();
    }, 30000);
  });
}).connect({
  host: 'localhost',
  port: 2222,
  username: 'test',
  password: 'test'
});

conn.on('error', (err) => {
  console.error('❌ 连接错误:', err.message);
});