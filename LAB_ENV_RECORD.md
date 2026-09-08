# 靶场虚拟机部署记录

## 基础信息

| 项目 | 值 |
|------|-----|
| 虚拟机地址 | 192.168.124.130 |
| 用户 | test |
| 密码 | 123456 |
| 操作系统 | Ubuntu 20.04.6 LTS (Kernel 5.15.0-139-generic) |
| Docker版本 | Docker 26.1.3 |
| 默认靶场端口 | 1008 (已占用) |

## 部署项目

| 项目 | 值 |
|------|-----|
| 项目名称 | hermes-web-ui (Hermes Studio) |
| 项目仓库 | https://github.com/EKKOLearnAI/hermes-studio.git (npm包名: hermes-web-ui, v0.7.18) |
| 描述 | 多Agent桌面/控制台前端，支持Hermes/Ekko/Claude Code/Codex/Pi |
| 技术栈 | Vue3 + Koa + TypeScript + Socket.IO |
| 要求 | Node.js >= 23.0.0 |

## 服务访问地址

| 访问方式 | URL |
|---------|-----|
| Web界面 | http://192.168.124.130:5000 |
| LAN URL | http://192.168.124.130:5000 (自动检测) |
| 默认登录账号 | admin / 123456 |
| Auth Token | 924d306fe6c3f5f4679befec9228d7151f1d90c72872017db62e76cf7f708f6b |

## 安装配置步骤

### 1. 环境检查
```bash
# 检查系统
uname -a    # Linux test 5.15.0-139-generic #149~20.04.1-Ubuntu SMP

# 检查已有Node.js
node --version    # v22.22.1 (不满足 >= 23 要求)
npm --version     # 10.9.4

# 检查Docker环境 (已预装)
docker --version  # Docker version 26.1.3

# 检查端口占用
ss -tlnp          # 端口1008被靶场默认服务占用
```

### 2. 网络问题排查与解决
```
问题：VM无法直接访问github.com (443端口连接被拒)
解决：在本地Windows克隆后通过SFTP传输到VM

诊断过程：
- ping github.com 正常 (20.205.243.166)
- 端口80/22可达，443端口被拒
- VM上有本地代理(8080/8888)但CONNECT隧道被拒
- git clone通过代理失败：Received HTTP code 400 from proxy after CONNECT

最终方案：
- Windows本地: git clone --depth 1 https://github.com/EKKOLearnAI/hermes-studio.git hermes-web-ui
- Compress-Archive打包为zip
- paramiko SFTP上传到 /home/test/hermes-web-ui.zip
- VM上解压: unzip hermes-web-ui.zip
```

### 3. 升级Node.js至v23.11.1 (使用nvm)
```bash
# NodeSource方式失败 - Ubuntu 20.04源仅提供到Node 22
# 改用nvm安装Node 23

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

nvm install 23
nvm use 23
nvm alias default 23

# 验证
node --version   # v23.11.1
npm --version    # 10.9.2
```

### 4. 安装项目依赖
```bash
cd ~/hermes-web-ui
npm install --legacy-peer-deps
# 安装557个依赖包，耗时约3-5分钟
```

### 5. 构建项目
```bash
cd ~/hermes-web-ui
npm run build
# 构建输出：
#   dist/client/    - Vue3前端
#   dist/server/index.js  - Koa后端服务 (11.1MB)
# 构建耗时约30秒
```

### 6. 创建systemd服务
```bash
cat > /tmp/hermes-ui.service << 'EOF'
[Unit]
Description=Hermes Web UI Service
After=network.target

[Service]
Type=simple
User=test
Group=test
WorkingDirectory=/home/test/hermes-web-ui

Environment=NVM_DIR=/home/test/.nvm
Environment=PATH=/home/test/.nvm/versions/node/v23.11.1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

Environment=PORT=5000
Environment=BIND_HOST=0.0.0.0
Environment=HERMES_WEB_UI_HOME=/home/test/.hermes-web-ui
Environment=LOG_LEVEL=info

ExecStart=/home/test/.nvm/versions/node/v23.11.1/bin/node /home/test/hermes-web-ui/dist/server/index.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo cp /tmp/hermes-ui.service /etc/systemd/system/hermes-web-ui.service
sudo systemctl daemon-reload
sudo systemctl enable hermes-web-ui
sudo systemctl start hermes-web-ui
```

### 7. 验证服务
```bash
# 检查服务状态
systemctl is-active hermes-web-ui     # active
systemctl is-enabled hermes-web-ui     # enabled

# 检查端口监听
ss -tlnp | grep 5000
# LISTEN  0  511  0.0.0.0:5000  users:(("MainThread",pid=52211,fd=25))

# 检查HTTP响应
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000    # 200

# 查看journal日志
journalctl -u hermes-web-ui --no-pager
# [bootstrap] Server: http://localhost:5000 (LAN: http://192.168.124.130:5000)
# [bootstrap] startup complete
```

## 修改的配置项

| 配置项 | 值 | 说明 |
|--------|-----|------|
| PORT | 5000 | 服务监听端口（避开靶场默认1008） |
| BIND_HOST | 0.0.0.0 | 绑定所有网卡 |
| HERMES_WEB_UI_HOME | /home/test/.hermes-web-ui | 数据存储目录 |
| LOG_LEVEL | info | 日志级别 |
| NODE版本 | v23.11.1 (nvm) | 满足项目>=23要求 |
| AUTH_TOKEN | 自动生成 | 位于 /home/test/.hermes-web-ui/.token |

## 流程守护配置

使用 systemd 服务守护，配置如下：
- **服务名**: hermes-web-ui.service
- **自动启动**: 已 enable (开机自启)
- **崩溃重启**: Restart=on-failure, RestartSec=5
- **运行用户**: test
- **进程ID**: 52211
- **日志**: journalctl -u hermes-web-ui.service

## 文件位置

| 路径 | 用途 |
|------|------|
| /home/test/hermes-web-ui/ | 项目源码目录 |
| /home/test/hermes-web-ui/dist/server/index.js | 服务入口文件 |
| /home/test/.hermes-web-ui/ | 运行时数据目录 |
| /home/test/.hermes-web-ui/.token | Bearer认证Token |
| /home/test/.hermes-web-ui/logs/server.log | 服务日志 |
| /home/test/.hermes-web-ui/hermes-web-ui.db | SQLite数据库 |
| /etc/systemd/system/hermes-web-ui.service | systemd服务定义 |

## 遇到的问题与解决

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| git clone失败 (GnuTLS recv error) | VM无法访问github.com 443 | 本地Windows克隆后SFTP传输 |
| NodeSource 23安装失败 | Ubuntu 20.04源仅到Node 22 | 改用nvm安装Node 23.11.1 |
| systemd报告Succeeded后退出 | CLI进程fork后退出，Type=simple不匹配 | 直接运行dist/server/index.js，不再使用CLI wrapper |

## 常用运维命令

```bash
# 服务管理
sudo systemctl start hermes-web-ui
sudo systemctl stop hermes-web-ui
sudo systemctl restart hermes-web-ui
systemctl status hermes-web-ui

# 日志查看
journalctl -u hermes-web-ui -f -n 50
tail -f /home/test/.hermes-web-ui/logs/server.log

# 进程检查
ps aux | grep hermes-web-ui
ss -tlnp | grep 5000

# 查看Token
cat /home/test/.hermes-web-ui/.token

# 重启并重置默认登录
hermes-web-ui reset-default-login
```
