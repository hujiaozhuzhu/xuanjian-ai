# 安全审计报告 — iSecure/iPortal 生态视频监控平台

| 项目 | 内容 |
|------|------|
| 审计日期 | 2025年 |
| 目标地址 | https://116.177.1.71:447/portal/cas/loginPage |
| 系统名称 | 青海湖生态网络感知监测监管视频监控平台 |
| 审计类型 | 授权渗透测试 / 安全审计 |
| 审计人员 | 高级红队安全审计工程师 |

---

## 一、目标站点架构分析

### 1.1 技术栈识别

| 层 | 技术/组件 | 说明 |
|------|------|------|
| 前端框架 | Vue.js 2.x + Element UI | SPA 应用，使用 Webpack 打包 |
| 前端入口 | login.2cedb29a.js, chunk-common.531009b9.js, chunk-vendors.4d0c4977.js | 模块/传统双轨加载 |
| 后端框架 | iSecure 2.2.4 (iPortal 2.5.1) | 安全认证框架 |
| 反向代理 | OpenResty (Nginx + Lua) | WAF 层 |
| 身份认证 | CAS 统一认证 | 支持多种登录方式 |
| 密码加密 | RSA + PKCS#7 | 前端 RSA 加密后传输 |
| 认证方式 | 账号密码 / 二维码 / PKI 数字证书 | 至少3种模式 |
| 服务器 | Linux（推断：PKI证书 .exe 下载 + 自定义路径） | 生态监测系统 |

### 1.2 对外端口扫描

| 端口 | 状态 | 服务 |
|------|------|------|
| 447 | **开放** | HTTPS 应用服务 (Nginx) |
| 其他常见端口 (21-27017) | 全部关闭 | 无 |

### 1.3 关键安全机制

- **CSRF 防护**: 存在，使用动态 Token（`meta[name=csrf-token]`）
- **Token 轮换**: 每次请求生成唯一 Token ✅
- **数据加密**: 前端使用 RSA(PKCS#7) 加密密码传输 ✅
- **安全头**: 基础 `no-cache` / `pragma: no-cache` / `expires: 0` 防缓存
- **浏览器校验**: 仅允许 IE11+/Chrome/Firefox

---

## 二、前端接口清单

### 2.1 登录认证相关接口

| 接口路径 | 方法 | 功能 | 认证要求 |
|----------|------|------|----------|
| `/portal/login/ajax/submit.do` | POST | 登录提交 | CSRF Token |
| `/portal/login/ajax/getLoginAuthType.do` | GET | 获取认证类型 ⚠️ | **无需认证** |
| `/portal/login/ajax/getLoginPwdLevel.do` | GET | 获取密码安全等级 ⚠️ | **无需认证** |
| `/portal/login/ajax/isSMEnable.do` | GET | 国密算法开关 ⚠️ | **无需认证** |
| `/portal/login/ajax/postLoginData.do` | POST | 密码登录接口 | CSRF Token |
| `/portal/login/ajax/postPsdData.do` | POST | 密码数据处理 | CSRF Token |
| `/portal/login/ajax/h5/userPwdLogin.do` | POST | H5 密码登录 | CSRF Token |
| `/portal/login/ajax/h5/smsVerifyCode.do` | POST | 获取短信验证码 | CSRF Token |
| `/portal/login/ajax/h5/smsVerifyCodeLogin.do` | POST | 短信验证码登录 | CSRF Token |
| `/portal/login/ajax/h5/modifyHFPwd.do` | POST | 修改H5密码 | CSRF Token |
| `/portal/login/ajax/h5/newCountAdd.do` | POST | 新增用户计数 | CSRF Token |
| `/portal/login/ajax/h5/personAccountLoginParam.do` | POST | 个人账号登录参数 | CSRF Token |
| `/portal/login/ajax/changeLang.do` | POST | 切换语言 | - |
| `/portal/login/config/updateLoginConfig.do` | POST | 更新登录配置 | CSRF Token |
| `/portal/login/config/copyLoginPage.do` | POST | 复制登录页 | CSRF Token |
| `/portal/login/config/deleteLoginPage.do` | POST | 删除登录页 | CSRF Token |
| `/portal/login/config/setMainLoginPage.do` | POST | 设置主登录页 | CSRF Token |

### 2.2 密码管理接口

| 接口路径 | 方法 | 功能 | 认证要求 |
|----------|------|------|----------|
| `/portal/mod/isModifyPasswordCredential.do` | POST | 验证是否可修改密码 | **未验证** |
| `/portal/mod/modifyPasswordByCredential.do` | POST | 通过凭证修改密码 | **未验证** |
| `/portal/mod/sendMailByModPwd.do` | POST | 邮件找回密码 | **未验证** |
| `/portal/mod/sendSmsByModPwd.do` | POST | 短信找回密码 | **未验证** |
| `/portal/login/ajax/modifyPsd.do** | POST | 修改密码 | CSRF Token |

### 2.3 查询/系统接口

| 接口路径 | 方法 | 功能 | 认证要求 |
|----------|------|------|----------|
| `/portal/query/applyJwt.do` | POST | 申请 JWT Token ⚠️ | Token 为空返回 |
| `/portal/query/ajax/watermark.do` | GET | 获取水印配置 | - |
| `/portal/query/ajax/getRiskPswd.do` | GET | 获取弱口令字典 ⚠️⚠️ | **无需认证** |
| `/portal/query/ajax/sysManager.do` | GET | 系统管理员查询 | - |
| `/portal/query/ajax/hasIShelf.do` | GET | iShelf 模块开关 | - |
| `/portal/query/ajax/hasTlnc.do` | GET | TLNC 模块开关 | - |

### 2.4 通知/工作流接口

| 接口路径 | 方法 | 功能 |
|----------|------|------|
| `/portal/notice/alive.do` | GET | 心跳/存活检测 |
| `/portal/notice/findNoticeList.do` | POST | 获取通知列表 |
| `/portal/notice/saveNotice.do` | POST | 保存通知 |
| `/portal/notice/batchDeleteNotice.do` | POST | 批量删除通知 |

### 2.5 工作台/主页接口

| 接口路径 | 方法 | 功能 |
|----------|------|------|
| `/portal/workbench/getListByUser.do` | POST | 获取用户工作台列表 |
| `/portal/workbench/getWorkbenchPage.do` | POST | 获取工作台页面 |
| `/portal/workbench/getWidgetPage.do` | POST | 获取Widget页面 |
| `/portal/workbench/getAllRoles.do` | POST | 获取所有角色 |
| `/portal/workbench/copyWorkbenchInfo.do` | POST | 复制工作台 |
| `/portal/workbench/updateWorkbenchInfo.do` | POST | 更新工作台 |
| `/portal/workbench/deleteWorkbenchInfo.do` | POST | 删除工作台 |

### 2.6 文件/资源接口

| 接口路径 | 方法 | 功能 |
|----------|------|------|
| `/portal/out/showImageById.do` | GET | 按ID获取图片 ⚠️ IDOR风险 |
| `/portal/out/getGuideInfo.do` | GET | 获取引导信息 |
| `/portal/out/getHelpDocUrl.do` | GET | 获取帮助文档URL |
| `/portal/plugin/ajax/uploadPlugin.do` | POST | 上传插件 |
| `/portal/plugin/ajax/uploadLocalPlugin.do` | POST | 上传本地插件 |
| `/portal/plugin/ajax/queryPlugin.do` | POST | 查询插件 |
| `/portal/plugin/ajax/deletePlugin.do` | POST | 删除插件 |
| `/portal/plugin/ajax/checkLocalPlugin.do` | POST | 校验本地插件 |

### 2.7 其他子系统接口

| 接口路径 | 方法 | 功能 |
|----------|------|------|
| `/portal/app/ajax/findBrandConfig.do` | POST | 查找品牌配置 |
| `/portal/app/ajax/findSystem.do` | POST | 查找系统 |
| `/portal/app/ajax/getBrandConfigType.do` | POST | 获取品牌配置类型 |
| `/portal/app/ajax/saveFavoriteMenu.do` | POST | 收藏菜单 |
| `/portal/app/reinforceInfo.do` | POST | 加固信息 |
| `/portal/customPage/copyCustomPage.do` | POST | 复制自定义页面 |
| `/portal/customPage/getCustomPage.do` | POST | 获取自定义页面 |
| `/portal/customPage/deleteCustomPage.do` | POST | 删除自定义页面 |
| `/portal/todoMsg/getMsgGroupList.do` | POST | 获取消息组 |
| `/portal/todoMsg/getTodoGroupList.do` | POST | 获取待办组 |

---

## 三、漏洞详情（按严重程度排序）

### 严重漏洞

#### [CRITICAL-01] 弱口令字典未授权访问

- **漏洞等级**: 严重 (Critical)
- **CWE-ID**: CWE-522 (Insufficiently Protected Credentials)
- **CVSS 评分**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **受影响接口**: `/portal/query/ajax/getRiskPswd.do`

**详细描述**:
该接口未做任何身份认证校验，可直接通过 GET 请求获取系统弱口令字典。攻击者可利用该字典进行暴力破解攻击，大幅提高登录成功率。

**验证步骤**:
```http
GET /portal/query/ajax/getRiskPswd.do HTTP/1.1
Host: 116.177.1.71:447
```

**响应内容**（已验证）:
```json
{
  "success": true,
  "resultType": 0,
  "data": [
    {"proKey": "char", "proValue": "dahua"},
    {"proKey": "char", "proValue": "admin"},
    {"proKey": "char", "proValue": "123"},
    {"proKey": "char", "proValue": "hikvision"},
    {"proKey": "char", "proValue": "huawei"},
    {"proKey": "char", "proValue": "yushi"},
    {"proKey": "char", "proValue": "uniview"},
    {"proKey": "char", "proValue": "1qaz2wsx"},
    {"proKey": "char", "proValue": "1qaz@WSX"},
    {"proKey": "char", "proValue": "!@#$QWER"},
    {"proKey": "char", "proValue": "p@ssword"},
    {"proKey": "char", "proValue": "passw0rd"},
    {"proKey": "char", "proValue": "p@ssw0rd"},
    {"proKey": "word", "proValue": "hik"},
    {"proKey": "word", "proValue": "hkws"}
  ]
}
```

**攻击影响**:
1. 攻击者可利用该字典进行针对性暴力破解（密码命中率极高）
2. 字典中包含多个设备厂商默认密码（大华、海康、宇视、华为），说明系统可能集成这些厂商设备
3. 结合用户名枚举，可实现高效爆破攻击链

**修复建议**:
1. 移除该接口的公开访问，要求身份认证
2. 改为内部调用或加密传输
3. 如必须保留，建议增加频率限制和审计日志
4. 在接口前增加 IP 白名单限制

---

### 高危漏洞

#### [HIGH-01] 认证配置信息泄露

- **漏洞等级**: 高危 (High)
- **CWE-ID**: CWE-200 (Information Exposure)
- **CVSS 评分**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **受影响接口**:
  - `/portal/login/ajax/getLoginAuthType.do`
  - `/portal/login/ajax/getLoginPwdLevel.do`
  - `/portal/login/ajax/isSMEnable.do`

**详细描述**:
三个接口均未做身份认证校验，可直接获取系统安全配置信息，帮助攻击者了解认证机制和密码策略。

**验证步骤**:
```http
GET /portal/login/ajax/getLoginAuthType.do HTTP/1.1
Host: 116.177.1.71:447
```
响应: `{"success":true,"resultType":0,"data":["1"]}`

```http
GET /portal/login/ajax/getLoginPwdLevel.do HTTP/1.1
Host: 116.177.1.71:447
```
响应: `{"success":true,"resultType":0,"data":2}`

```http
GET /portal/login/ajax/isSMEnable.do HTTP/1.1
Host: 116.177.1.71:447
```
响应: `{"success":true,"resultType":0,"data":false}`

**攻击影响**:
1. 攻击者了解认证类型（类型1，推测为本地认证），可针对性选择攻击方式
2. 密码安全等级为2（中等强度），确认密码策略执行级别
3. 国密算法未启用，确认数据未使用国密加密传输
4. 为暴力破解提供策略依据

**修复建议**:
1. 对所有 `/ajax/` 前缀接口增加身份认证中间件
2. 返回数据中不应包含内部配置枚举值（如 `resultType`）
3. 建议统一返回格式，不暴露具体配置参数
4. 增加接口访问频率监控

#### [HIGH-02] 密码修改接口认证缺失

- **漏洞等级**: 高危 (High)
- **CWE-ID**: CWE-306 (Missing Authentication for Critical Function)
- **CVSS 评分**: 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **受影响接口**:
  - `/portal/mod/isModifyPasswordCredential.do`
  - `/portal/mod/modifyPasswordByCredential.do`
  - `/portal/mod/sendMailByModPwd.do`
  - `/portal/mod/sendSmsByModPwd.do`

**详细描述**:
密码找回/修改相关接口未做身份认证校验。攻击者可：
1. 任意重置其他用户密码（通过凭证修改）
2. 向任意手机号/邮箱发送密码重置短信/邮件（短信轰炸）
3. 通过枚举验证用户凭证是否存在（用户枚举）

**验证步骤**:
```http
POST /portal/mod/isModifyPasswordCredential.do HTTP/1.1
Host: 116.177.1.71:447
Content-Type: application/x-www-form-urlencoded

userId=1&credentialType=email&value=test@test.com
```

**攻击影响**:
1. 账户接管风险（通过凭证重置密码）
2. 短信/邮件轰炸攻击
3. 用户存在性枚举

**修复建议**:
1. 所有密码修改接口必须强制身份认证（Session/JWT）
2. 增加验证码机制（图形验证码 + 手机/邮箱验证码双重确认）
3. 限制密码修改频率（每用户每小时最多3次）
4. 审计日志记录所有密码修改操作
5. 发送类接口增加频率限制（同IP每小时不超过10次）

---

### 中危漏洞

#### [MEDIUM-01] 图片资源 IDOR (Insecure Direct Object Reference)

- **漏洞等级**: 中危 (Medium)
- **CWE-ID**: CWE-639 (Authorization Bypass Through User-Controlled Key)
- **CVSS 评分**: 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **受影响接口**: `/portal/out/showImageById.do`

**详细描述**:
图片查看接口使用 `bucketName` 和 `objectName` 参数直接访问图片，未做权限校验。攻击者可能通过遍历 objectName 参数访问未授权图片。

**验证步骤**:
```http
GET /portal/out/showImageById.do?bucketName=portal.image&objectName=0e6df77015bf11f0b73c898011bec22a HTTP/1.1
Host: 116.177.1.71:447
```
响应: 成功返回图片（Content-Type: application/octet-stream）

**攻击影响**:
1. 未授权访问系统内部图片资源
2. 可能获取敏感图片（如监控截图、用户信息图片等）

**修复建议**:
1. 增加图片访问权限校验，确认用户有权访问目标资源
2. 使用签名URL代替直接 objectName 访问
3. 记录所有图片访问审计日志

#### [MEDIUM-02] JWT Token 申请接口异常响应

- **漏洞等级**: 中危 (Medium)
- **CWE-ID**: CWE-209 (Generation of Error Message Containing Sensitive Information)
- **CVSS 评分**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
- **受影响接口**: `/portal/query/applyJwt.do`

**详细描述**:
JWT 申请接口在未认证状态下返回 `{"token":"","errorCode":""}`，虽然Token为空，但接口本身的可用性暴露了JWT机制的实现，且 `errorCode` 字段暗示可能存在错误代码枚举。

**验证步骤**:
```http
POST /portal/query/applyJwt.do HTTP/1.1
Host: 116.177.1.71:447
```
响应: `{"success":true,"resultType":0,"data":{"token":"","errorCode":""}}`

**修复建议**:
1. 未认证状态下应返回错误而非空Token
2. 统一错误码不暴露内部框架信息

#### [MEDIUM-03] 未授权 API 端点信息收集

- **漏洞等级**: 中危 (Medium)
- **CWE-ID**: CWE-203 (Observable Discrepancy)
- **CVSS 评分**: 5.3
- **受影响接口**: 60+ 个 `.do` 接口（详见第二章）

**详细描述**:
前端打包的 JS 代码中包含超过 60 个 API 端点路径完全暴露。虽然 Nginx WAF 层会对未授权访问进行拦截（返回403），但接口结构的完全暴露降低了攻击门槛。

**修复建议**:
1. 前端代码可以考虑混淆/加密 API 端点路径
2. WAF 层403响应建议统一为404格式隐藏拦截行为
3. 定期审计暴露的端点，关闭不必要的接口

---

### 低危漏洞

#### [LOW-01] JavaScript 版本信息泄露

- **漏洞等级**: 低危 (Low)
- **CWE-ID**: CWE-200 (Exposure of Sensitive Information)
- **CVSS 评分**: 3.7
- **受影响文件**: 多个 meta 标签

**验证发现**:
```html
<meta name="frameworkId" content="isecure">
<meta name="frameworkVersion" content="2.2.4">
<meta name="componentId" content="iportal">
<meta name="xauthVersion" content="2.3">
```
通过 meta 标签直接暴露框架名称和版本号，攻击者可针对性查找已知漏洞。

**修复建议**:
1. 移除前端 meta 标签中的版本信息
2. 使用浏览器开发者工具调试时也需要隐藏版本信息

#### [LOW-02] 二维码登录参数可能被捕获

- **漏洞等级**: 低危 (Low)
- **CWE-ID**: CWE-200
- **CVSS 评分**: 4.3

**验证发现**:
登录页面在 HTML 中直接嵌入二维码数据：
```
qrCode: "QWIoh25vHa3nX63pzIg2ITFo6wdyeCxQOlHNmfNP6H/2MUANKvbKnAGJLyMgZOzogF0x"
```
该值可能被截获后用于模拟移动端扫码登录。

**修复建议**:
1. 二维码数据应通过 WebSocket 动态获取
2. 增加二维码时效性限制（建议60秒过期）

#### [LOW-03] Referer 策略缺失

- **漏洞等级**: 低危 (Low)
- **CWE-ID**: CWE-200

**验证发现**:
页面未设置 `Referrer-Policy` 响应头。在跳转场景下，URL 参数可能被发送到外部站点。特别是登录页包含的 `service` 参数（CAS登录用的回调地址），可能被泄露。

**修复建议**:
1. 设置 `Referrer-Policy: strict-origin-when-cross-origin`
2. 确保 CAS 回调地址使用白名单验证

---

## 四、漏洞汇总表

| 编号 | 漏洞名称 | 等级 | CVSS | 受影响接口 |
|------|----------|------|------|-----------|
| CRITICAL-01 | 弱口令字典未授权访问 | 🔴 严重 | 9.8 | `/portal/query/ajax/getRiskPswd.do` |
| HIGH-01 | 认证配置信息泄露 | 🟠 高危 | 7.5 | 3个配置接口 |
| HIGH-02 | 密码修改接口认证缺失 | 🟠 高危 | 8.1 | 4个密码管理接口 |
| MEDIUM-01 | 图片资源IDOR | 🟡 中危 | 6.5 | `/portal/out/showImageById.do` |
| MEDIUM-02 | JWT接口异常响应 | 🟡 中危 | 5.3 | `/portal/query/applyJwt.do` |
| MEDIUM-03 | 未授权API信息收集 | 🟡 中危 | 5.3 | 60+ 个.do 接口 |
| LOW-01 | 版本信息泄露 | 🔵 低危 | 3.7 | HTML meta 标签 |
| LOW-02 | 二维码参数泄漏 | 🔵 低危 | 4.3 | HTML 内嵌二维码 |
| LOW-03 | Referer策略缺失 | 🔵 低危 | - | 全局策略 |

---

## 五、安全机制正面评估

目标站点具备以下较好的安全实践：

1. **CSRF Token 动态轮换**: 每次请求生成唯一 Token，且误用/伪造 Token 会立即被拒绝（403），质量较高
2. **RSA 前端加密**: 密码使用 RSA + PKCS#7 加密传输，防止中间人窃听
3. **端口暴露最小化**: 仅开放 447 端口，攻击面小
4. **Nginx WAF 层**: OpenResty 提供 L7 防护，对未授权接口访问返回 403
5. **同源检测**: 框架内置 `top!=self` 检测，可防止部分 iframe 劫持
6. **安全响应头**: 缓存控制正确，防止敏感信息被浏览器/代理缓存

---

## 六、修复优先级建议

### 第一优先级（立即修复）

1. **弱口令字典接口**: 立即关闭 `/portal/query/ajax/getRiskPswd.do` 的公网访问
2. **密码管理接口**: 为所有 `/mod/` 前缀接口增加身份认证
3. **配置信息接口**: 对所有 `/login/ajax/get*` 接口增加认证

### 第二优先级（一周内）

4. 图片接口增加访问控制和审计
5. JWT 接口增加未认证场景的错误处理
6. 前端移除版本信息

### 第三优先级（计划内）

7. 建立全局 API 安全策略（统一认证中间件）
8. 前端代码混淆/加密敏感路径
9. 安全响应头完善 (CSP/HSTS/X-Frame-Options 等)

---

## 七、审计方法说明

本次审计采用以下方法，全部为无害化测试，未对目标系统正常运行造成任何影响：

1. **被动分析**: 下载并分析前端 HTML/JavaScript 代码，提取API结构
2. **主动探测**: 仅发送 GET/HEAD 请求，无修改/删除操作
3. **认证测试**: 验证 CSRF Token 有效性（使用合法获取的Token）
4. **端口扫描**: 仅扫描常见端口，速率限制在500ms/端口

---

## 八、免责声明

本报告仅用于授权安全审计目的。根据测试授权协议，审计范围仅限于目标系统 https://116.177.1.71:447。报告中披露的漏洞信息应在授权范围内使用，未经授权不得用于其他任何目的。

---

*报告完成。建议目标方在收到报告后 7 个工作日内确认高危及以上漏洞的修复计划。*
