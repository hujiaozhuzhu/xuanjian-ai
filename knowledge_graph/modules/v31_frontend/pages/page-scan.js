/**
 * XuanJian v3.1 - Scan Center Page
 * Start scans, view progress, configure scanners
 */
(function (global) {
  'use strict';

  var isScanning = false;
  var scanResult = null;

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div>' +
            '<h2 class="xj-section-title">扫描中心</h2>' +
            '<span class="xj-text-muted">配置并启动安全扫描任务</span>' +
          '</div>' +
        '</div>' +

        // Scan Form
        '<div class="xj-panel" style="max-width:760px;">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">🚀 启动扫描</span></div>' +
          '<div class="xj-field">' +
            '<label class="xj-field-label">项目路径</label>' +
            '<input class="xj-input" id="xj-scan-path" type="text" placeholder="/path/to/your/project 或 C:\\projects\\myapp">' +
          '</div>' +
          '<div class="xj-grid-2">' +
            '<div class="xj-field">' +
              '<label class="xj-field-label">编程语言</label>' +
              '<select class="xj-select" id="xj-scan-lang">' +
                '<option value="auto">自动检测</option>' +
                '<option value="java">Java</option>' +
                '<option value="python">Python</option>' +
                '<option value="go">Go</option>' +
                '<option value="javascript">JavaScript</option>' +
                '<option value="typescript">TypeScript</option>' +
              '</select>' +
            '</div>' +
            '<div class="xj-field">' +
              '<label class="xj-field-label">预设规则集</label>' +
              '<select class="xj-select" id="xj-scan-ruleset">' +
                '<option value="full">完整规则 (推荐)</option>' +
                '<option value="owasp-top10">OWASP Top 10</option>' +
                '<option value="cwe-top25">CWE Top 25</option>' +
                '<option value="pii">个人信息保护</option>' +
              '</select>' +
            '</div>' +
          '</div>' +
          '<div class="xj-field">' +
            '<label class="xj-field-label">扫描工具</label>' +
            '<div class="xj-btn-group" style="flex-wrap:wrap;">' +
              '<label class="xj-tag" style="padding:6px 12px;cursor:pointer;"><input type="checkbox" checked style="margin-right:4px;" value="semgrep"> Semgrep</label>' +
              '<label class="xj-tag" style="padding:6px 12px;cursor:pointer;"><input type="checkbox" style="margin-right:4px;" value="bandit"> Bandit</label>' +
              '<label class="xj-tag" style="padding:6px 12px;cursor:pointer;"><input type="checkbox" style="margin-right:4px;" value="findsecbugs"> FindSecBugs</label>' +
              '<label class="xj-tag" style="padding:6px 12px;cursor:pointer;"><input type="checkbox" style="margin-right:4px;" value="gosec"> GoSec</label>' +
            '</div>' +
          '</div>' +
          '<button class="xj-btn xj-btn-primary xj-btn-lg" id="xj-scan-start-btn" onclick="XJPageScan.startScan()">' +
            '<span id="xj-scan-btn-text">▶ 开始扫描</span>' +
          '</button>' +
        '</div>' +

        // Progress Section
        '<div class="xj-panel" id="xj-scan-progress-panel" hidden>' +
          '<div class="xj-panel-header">' +
            '<span class="xj-panel-title" id="xj-scan-progress-title">扫描进度</span>' +
            '<span class="xj-tag status-pending" id="xj-scan-progress-tag">运行中</span>' +
          '</div>' +
          '<div style="background:var(--xj-bg-0);border-radius:6px;height:12px;overflow:hidden;">' +
            '<div id="xj-scan-progress-bar" style="background:var(--xj-blue);height:100%;width:0%;transition:width 0.5s ease;border-radius:6px;"></div>' +
          '</div>' +
          '<div class="xj-text-muted" style="margin-top:8px;" id="xj-scan-progress-msg">准备中...</div>' +
          '<div id="xj-scan-progress-result" style="margin-top:16px;" hidden></div>' +
        '</div>' +
      '</div>';

    UI.render(html);
  }

  function startScan() {
    if (isScanning) return;
    var path = document.getElementById('xj-scan-path').value.trim();
    if (!path) { UI.toast('请输入项目路径', 'error'); return; }

    isScanning = true;
    var btnText = document.getElementById('xj-scan-btn-text');
    var progressPanel = document.getElementById('xj-scan-progress-panel');
    var progressBar = document.getElementById('xj-scan-progress-bar');
    var progressMsg = document.getElementById('xj-scan-progress-msg');
    var progressTag = document.getElementById('xj-scan-progress-tag');
    var progressTitle = document.getElementById('xj-scan-progress-title');
    var resultDiv = document.getElementById('xj-scan-progress-result');

    if (btnText) btnText.textContent = '⏳ 扫描中...';
    progressPanel.removeAttribute('hidden');
    progressBar.style.width = '10%';
    progressMsg.textContent = '正在初始化扫描引擎...';
    progressTag.className = 'xj-tag status-pending';
    progressTag.textContent = '运行中';

    // Collect checked scanners
    var scanners = [];
    var mainEl = document.getElementById('xj-main');
    var checks = mainEl.querySelectorAll('input[type="checkbox"]:checked');
    checks.forEach(function(c) { scanners.push(c.value); });

    var lang = document.getElementById('xj-scan-lang').value;

    // Simulate progress (real: connect to API)
    var progress = 10;
    var phases = ['解析代码结构...', 'Semgrep 规则匹配...', '上下文过滤分析...', 'AI误报判定中...', '生成报告...'];
    var phaseIdx = 0;

    var progressInterval = setInterval(function() {
      progress += Math.random() * 15 + 5;
      if (progress > 95) progress = 95;
      progressBar.style.width = progress + '%';
      progressMsg.textContent = phases[Math.min(phaseIdx, phases.length - 1)] + ' (' + Math.round(progress) + '%)';
      if (progress > (phaseIdx + 1) * 20 && phaseIdx < phases.length - 1) phaseIdx++;
    }, 800);

    // API call
    API.startScan(path, lang, scanners.length > 0 ? scanners : null)
      .then(function(data) {
        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        progressMsg.textContent = '扫描完成！';
        progressTag.className = 'xj-tag status-closed';
        progressTag.textContent = '已完成';
        progressTitle.textContent = '扫描结果';

        resultDiv.removeAttribute('hidden');
        resultDiv.innerHTML =
          '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;">' +
            '<div style="text-align:center;padding:12px;background:var(--xj-bg-0);border-radius:6px;"><div style="font-size:22px;font-weight:700;color:var(--xj-blue);">' + XSS.escapeHtml(String(data.total_findings || 0)) + '</div><div class="xj-text-muted">总发现</div></div>' +
            '<div style="text-align:center;padding:12px;background:var(--xj-bg-0);border-radius:6px;"><div style="font-size:22px;font-weight:700;color:var(--xj-green);">' + XSS.escapeHtml(data.duration_seconds ? data.duration_seconds + 's' : '-') + '</div><div class="xj-text-muted">耗时</div></div>' +
            '<div style="text-align:center;padding:12px;background:var(--xj-bg-0);border-radius:6px;"><div style="font-size:22px;font-weight:700;color:var(--xj-red);">' + XSS.escapeHtml(data.statistics && data.statistics.reduction_rate ? data.statistics.reduction_rate : '-') + '</div><div class="xj-text-muted">减少率</div></div>' +
            '<div style="text-align:center;padding:12px;background:var(--xj-bg-0);border-radius:6px;"><div style="font-size:22px;font-weight:700;color:var(--xj-orange);">' + XSS.escapeHtml(String(data.scan_id ? data.scan_id.slice(0,8) : '-')) + '</div><div class="xj-text-muted">扫描ID</div></div>' +
          '</div>' +
          '<button class="xj-btn xj-btn-primary" onclick="Router.navigate(\'/findings?scan_id=' + XSS.escapeAttr(data.scan_id) + '\')">查看发现列表 &rarr;</button>';

        scanResult = data;
        UI.toast('扫描完成，共发现 ' + (data.total_findings || 0) + ' 项', 'success');

        // Connect event stream for real progress
        if (typeof EventStream !== 'undefined' && data.scan_id) {
          EventStream.connect(data.scan_id);
        }
      })
      .catch(function(err) {
        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        progressBar.style.background = 'var(--xj-red)';
        progressMsg.textContent = '扫描失败: ' + err.message;
        progressTag.className = 'xj-tag status-open';
        progressTag.textContent = '失败';
        UI.toast('扫描失败: ' + err.message, 'error');
      })
      .finally(function() {
        isScanning = false;
        if (btnText) btnText.textContent = '▶ 开始扫描';
      });
  }

  XJPages.add({
    path: '/scan',
    title: '扫描中心',
    navLabel: '扫描中心',
    render: render
  });

  global.XJPageScan = { startScan: startScan };
})(window);
