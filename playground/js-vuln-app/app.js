/**
 * 玄鉴 JS 靶场应用
 *
 * 包含 6 种常见漏洞类型，用于验证 JS 扫描器检出能力
 * 每种漏洞包含：不安全实现 + 安全实现（用于误报测试）
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = "weak123";  // 🔴 漏洞: JWT弱密钥
const API_KEY = "sk-1234567890abcdef";  // 🔴 漏洞: 硬编码密钥

// ─────────────────────── 1. XSS 漏洞 ───────────────────────

// 🔴 不安全: innerHTML 直接赋值
app.get('/xss/unsafe', (req, res) => {
    const userInput = req.query.input || '';
    res.send(`
        <div id="output"></div>
        <script>
            document.getElementById('output').innerHTML = '${userInput}';
        </script>
    `);
});

// ✅ 安全: textContent 赋值
app.get('/xss/safe', (req, res) => {
    const userInput = req.query.input || '';
    res.send(`
        <div id="output"></div>
        <script>
            document.getElementById('output').textContent = '${userInput}';
        </script>
    `);
});

// ─────────────────────── 2. 代码注入 ───────────────────────

// 🔴 不安全: eval 执行用户输入
app.get('/eval/unsafe', (req, res) => {
    const code = req.query.code || '1+1';
    const result = eval(code);  // 🔴 漏洞
    res.json({ result });
});

// ✅ 安全: JSON.parse
app.get('/eval/safe', (req, res) => {
    const data = req.query.data || '{}';
    try {
        const result = JSON.parse(data);  // ✅ 安全
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'Invalid JSON' });
    }
});

// ─────────────────────── 3. 命令注入 ───────────────────────

// 🔴 不安全: exec 拼接用户输入
app.get('/cmd/unsafe', (req, res) => {
    const cmd = req.query.cmd || 'ls';
    exec(cmd, (error, stdout, stderr) => {  // 🔴 漏洞
        res.json({ stdout, stderr });
    });
});

// ✅ 安全: 白名单验证
app.get('/cmd/safe', (req, res) => {
    const cmd = req.query.cmd || 'ls';
    const allowed = ['ls', 'pwd', 'whoami'];
    if (!allowed.includes(cmd)) {
        return res.status(403).json({ error: 'Command not allowed' });
    }
    exec(cmd, (error, stdout, stderr) => {
        res.json({ stdout, stderr });
    });
});

// ─────────────────────── 4. SQL 注入 ───────────────────────

// 🔴 不安全: 字符串拼接SQL
app.get('/sql/unsafe', (req, res) => {
    const userId = req.query.id;
    const sql = "SELECT * FROM users WHERE id = " + userId;  // 🔴 漏洞
    // db.query(sql);
    res.json({ query: sql });
});

// ✅ 安全: 参数化查询
app.get('/sql/safe', (req, res) => {
    const userId = req.query.id;
    const sql = "SELECT * FROM users WHERE id = ?";
    // db.query(sql, [userId]);
    res.json({ query: sql, params: [userId] });
});

// ─────────────────────── 5. SSRF ───────────────────────

// 🔴 不安全: 请求用户指定的URL
app.get('/ssrf/unsafe', async (req, res) => {
    const url = req.query.url;
    try {
        const response = await axios.get(url);  // 🔴 漏洞
        res.json({ data: response.data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ✅ 安全: URL白名单验证
app.get('/ssrf/safe', async (req, res) => {
    const url = req.query.url;
    const allowed = ['https://api.example.com', 'https://data.example.com'];
    if (!allowed.some(a => url.startsWith(a))) {
        return res.status(403).json({ error: 'URL not allowed' });
    }
    try {
        const response = await axios.get(url);
        res.json({ data: response.data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ─────────────────────── 6. 路径遍历 ───────────────────────

// 🔴 不安全: 直接拼接用户路径
app.get('/path/unsafe', (req, res) => {
    const filename = req.query.file;
    const filepath = path.join(__dirname, 'uploads', filename);  // 🔴 漏洞
    fs.readFile(filepath, (err, data) => {
        if (err) return res.status(404).json({ error: 'File not found' });
        res.send(data);
    });
});

// ✅ 安全: 路径规范化验证
app.get('/path/safe', (req, res) => {
    const filename = req.query.file;
    const filepath = path.join(__dirname, 'uploads', filename);
    const normalized = path.resolve(filepath);
    const baseDir = path.resolve(__dirname, 'uploads');
    if (!normalized.startsWith(baseDir)) {
        return res.status(403).json({ error: 'Access denied' });
    }
    fs.readFile(filepath, (err, data) => {
        if (err) return res.status(404).json({ error: 'File not found' });
        res.send(data);
    });
});

// ─────────────────────── 7. JWT 弱密钥 ───────────────────────

// 🔴 不安全: 弱密钥签名
app.post('/jwt/sign', (req, res) => {
    const payload = req.body;
    const token = jwt.sign(payload, JWT_SECRET);  // 🔴 漏洞
    res.json({ token });
});

// ✅ 安全: 强密钥
app.post('/jwt/sign-safe', (req, res) => {
    const payload = req.body;
    const strongSecret = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');
    const token = jwt.sign(payload, strongSecret, { algorithm: 'HS256' });
    res.json({ token });
});

// ─────────────────────── 启动服务 ───────────────────────

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`JS Vuln App running on port ${PORT}`);
});

module.exports = app;
