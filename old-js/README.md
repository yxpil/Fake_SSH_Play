# SSH音频蜜罐 - Bad Apple版本 🎵🍎

一个创新的SSH蜜罐，当攻击者连接时，会向他们传输Bad Apple音频文件而不是提供shell访问。

## 功能特点

- 🎵 **音频传输**: 通过SSH通道传输Bad Apple MP3音频
- 🍎 **ASCII艺术**: 显示Bad Apple主题的ASCII艺术横幅
- 📊 **进度显示**: 实时显示音频传输进度
- 🔒 **安全**: 使用SSH密钥认证，记录攻击日志
- ⚡ **超优化**: 8kbps压缩，312KB文件大小

## 文件说明

- `example.js` - SSH音频蜜罐主程序
- `ssh_ultra_optimized.mp3` - 超优化的Bad Apple音频文件 (8kbps, 312KB)
- `host_rsa.key` - SSH主机私钥
- `test_audio_client.js` - 测试客户端
- `badapple.txt` - ASCII艺术帧数据

## 使用方法

### 启动蜜罐服务器
```bash
sudo node example.js
```

### 测试连接
```bash
node test_audio_client.js
```

## 技术规格

- **音频格式**: MP3, 8kbps, 16kHz, 单声道
- **传输方式**: Base64编码，512字节块
- **SSH端口**: 2222
- **总文件大小**: 312KB (319,724字节)

## 传输效率

- 原始音频: 639KB → 优化后: 312KB (51%压缩)
- 传输时间: 约30秒 (通过SSH通道)
- 接收大小: 152KB (Base64编码后)

## 攻击者体验

当攻击者连接时，他们会看到：
- 精美的ASCII艺术欢迎界面
- Bad Apple音频实时传输
- 传输进度显示
- 友好的音乐播放完成消息

这个蜜罐将潜在的安全威胁转化为有趣的音频体验！🎶