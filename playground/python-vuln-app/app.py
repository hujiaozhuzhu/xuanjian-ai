"""
玄鉴 Python 靶场应用

包含 6 种常见漏洞类型，用于验证 Python 规则库检出能力
"""

import os
import pickle
import yaml
import hashlib
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_KEY = "hardcoded_secret_key_123"  # 🔴 漏洞: 硬编码密钥

# ─────────────────────── 1. SQL 注入 ───────────────────────

# 🔴 不安全: 字符串拼接SQL
@app.route('/sql/unsafe')
def sql_unsafe():
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = " + user_id  # 🔴 漏洞
    return jsonify({"query": query})

# ✅ 安全: 参数化查询
@app.route('/sql/safe')
def sql_safe():
    user_id = request.args.get('id')
    query = "SELECT * FROM users WHERE id = %s"
    return jsonify({"query": query, "params": [user_id]})

# ─────────────────────── 2. 命令注入 ───────────────────────

# 🔴 不安全: os.system 拼接
@app.route('/cmd/unsafe')
def cmd_unsafe():
    cmd = request.args.get('cmd', 'ls')
    os.system(cmd)  # 🔴 漏洞
    return jsonify({"status": "executed"})

# ✅ 安全: 白名单
@app.route('/cmd/safe')
def cmd_safe():
    cmd = request.args.get('cmd', 'ls')
    allowed = ['ls', 'pwd', 'whoami']
    if cmd not in allowed:
        return jsonify({"error": "not allowed"}), 403
    subprocess.run(cmd.split(), capture_output=True)
    return jsonify({"status": "executed"})

# ─────────────────────── 3. 代码注入 ───────────────────────

# 🔴 不安全: eval
@app.route('/eval/unsafe')
def eval_unsafe():
    code = request.args.get('code', '1+1')
    result = eval(code)  # 🔴 漏洞
    return jsonify({"result": result})

# ✅ 安全: ast.literal_eval
@app.route('/eval/safe')
def eval_safe():
    import ast
    code = request.args.get('code', '1+1')
    try:
        result = ast.literal_eval(code)  # ✅ 安全
        return jsonify({"result": result})
    except:
        return jsonify({"error": "invalid expression"}), 400

# ─────────────────────── 4. 反序列化 ───────────────────────

# 🔴 不安全: pickle.loads
@app.route('/deserialize/unsafe', methods=['POST'])
def deserialize_unsafe():
    data = request.get_data()
    obj = pickle.loads(data)  # 🔴 漏洞
    return jsonify({"data": str(obj)})

# ✅ 安全: json.loads
@app.route('/deserialize/safe', methods=['POST'])
def deserialize_safe():
    import json
    data = request.get_data()
    obj = json.loads(data)  # ✅ 安全
    return jsonify({"data": obj})

# ─────────────────────── 5. 弱哈希 ───────────────────────

# 🔴 不安全: MD5 密码哈希
@app.route('/hash/unsafe')
def hash_unsafe():
    password = request.args.get('password', '')
    hashed = hashlib.md5(password.encode()).hexdigest()  # 🔴 漏洞
    return jsonify({"hash": hashed})

# ✅ 安全: bcrypt
@app.route('/hash/safe')
def hash_safe():
    password = request.args.get('password', '')
    # hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    hashed = hashlib.sha256(password.encode()).hexdigest()  # 比MD5好
    return jsonify({"hash": hashed})

# ─────────────────────── 6. 路径遍历 ───────────────────────

# 🔴 不安全: 直接拼接路径
@app.route('/path/unsafe')
def path_unsafe():
    filename = request.args.get('file')
    filepath = os.path.join('uploads', filename)  # 🔴 漏洞
    try:
        with open(filepath) as f:
            return f.read()
    except:
        return jsonify({"error": "not found"}), 404

# ✅ 安全: 路径验证
@app.route('/path/safe')
def path_safe():
    filename = request.args.get('file')
    filepath = os.path.join('uploads', filename)
    realpath = os.path.realpath(filepath)
    base = os.path.realpath('uploads')
    if not realpath.startswith(base):
        return jsonify({"error": "access denied"}), 403
    try:
        with open(filepath) as f:
            return f.read()
    except:
        return jsonify({"error": "not found"}), 404

# ─────────────────────── 7. YAML 不安全加载 ───────────────────────

# 🔴 不安全: yaml.load
@app.route('/yaml/unsafe', methods=['POST'])
def yaml_unsafe():
    data = request.get_data().decode()
    result = yaml.load(data)  # 🔴 漏洞
    return jsonify({"data": result})

# ✅ 安全: yaml.safe_load
@app.route('/yaml/safe', methods=['POST'])
def yaml_safe():
    data = request.get_data().decode()
    result = yaml.safe_load(data)  # ✅ 安全
    return jsonify({"data": result})

# ─────────────────────── 启动 ───────────────────────

if __name__ == '__main__':
    app.run(port=3002, debug=False)
