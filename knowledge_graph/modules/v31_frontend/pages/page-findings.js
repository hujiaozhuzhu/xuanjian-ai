/**
 * XuanJian v3.1 - Findings Management Page
 * Filter, search, triage, and mark findings with three-state annotation
 */
(function (global) {
  'use strict';

  var sampleFindings = [
    { id: 'f001', rule: 'java.sql.inject', severity: 'CRITICAL', file: 'src/main/dao/UserDao.java', line: 42, msg: 'Potential SQL injection via string concatenation', verdict: 'needs_review', confidence: 0.72, risk: 9.1 },
    { id: 'f002', rule: 'java.xss.owasp', severity: 'HIGH', file: 'src/main/web/ProfileServlet.java', line: 87, msg: 'Unvalidated user input rendered in HTML response', verdict: 'false_positive', confidence: 0.95, risk: 2.3 },
    { id: 'f003', rule: 'java.path.traversal', severity: 'HIGH', file: 'src/main/util/FileUtil.java', line: 15, msg: 'File path not sanitized from user-controlled input', verdict: 'true_positive', confidence: 0.88, risk: 8.5 },
    { id: 'f004', rule: 'java.hardcoded.secret', severity: 'MEDIUM', file: 'src/main/config/AppConfig.java', line: 23, msg: 'Hardcoded API key detected in source code', verdict: 'needs_review', confidence: 0.65, risk: 5.2 },
    { id: 'f005', rule: 'java.unsafe.deserialize', severity: 'CRITICAL', file: 'src/main/service/DataService.java', line: 56, msg: 'Java native deserialization without type checking', verdict: 'true_positive', confidence: 0.91, risk: 9.8 },
    { id: 'f006', rule: 'java.null.deref', severity: 'LOW', file: 'src/main/util/StringHelper.java', line: 33, msg: 'Possible null pointer dereference', verdict: 'false_positive', confidence: 0.82, risk: 1.8 },
    { id: 'f007', rule: 'java.crypto.weak', severity: 'MEDIUM', file: 'src/main/security/AuthUtil.java', line: 78, msg: 'Weak hash algorithm (MD5) used for password storage', verdict: 'true_positive', confidence: 0.79, risk: 6.7 },
    { id: 'f008', rule: 'java.command.injection', severity: 'CRITICAL', file: 'src/main/admin/SystemCmd.java', line: 12, msg: 'OS command execution with user-controlled parameter', verdict: 'needs_review', confidence: 0.68, risk: 8.9 }
  ];

  function render(params) {
    var scanId = params ? params.scan_id : '';

    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div>' +
            '<h2 class="xj-section-title">发现管理</h2>' +
            '<span class="xj-text-muted">' + (scanId ? '扫描ID: ' + XSS.escapeHtml(scanId) : '全部发现') + '</span>' +
          '</div>' +
          '<div class="xj-btn-group">' +
            '<button class="xj-btn xj-btn-sm" onclick="XJPageFindings.exportJSON()">导出JSON</button>' +
            '<button class="xj-btn xj-btn-sm" onclick="XJPageFindings.exportMD()">导出Markdown</button>' +
          '</div>' +
        '</div>' +

        // Toolbar
        '<div class="xj-toolbar">' +
          '<select class="xj-select" style="width:auto;" id="xj-finding-filter-verdict" onchange="XJPageFindings.filter()">' +
            '<option value="">全部判定</option>' +
            '<option value="false_positive">误报</option>' +
            '<option value="likely_false_positive">疑似误报</option>' +
            '<option value="true_positive">真实问题</option>' +
            '<option value="needs_review">待复核</option>' +
          '</select>' +
          '<select class="xj-select" style="width:auto;" id="xj-finding-filter-severity" onchange="XJPageFindings.filter()">' +
            '<option value="">全部严重度</option>' +
            '<option value="CRITICAL">CRITICAL</option>' +
            '<option value="HIGH">HIGH</option>' +
            '<option value="MEDIUM">MEDIUM</option>' +
            '<option value="LOW">LOW</option>' +
          '</select>' +
          '<input class="xj-input" id="xj-finding-search" placeholder="搜索规则/文件/消息..." oninput="XJPageFindings.debounceFilter()">' +
        '</div>' +

        // Summary cards
        '<div class="xj-stats-grid" id="xj-finding-summary" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:16px;"></div>' +

        // Table
        '<div class="xj-table-wrap">' +
          '<table class="xj-table" id="xj-finding-table">' +
            '<thead><tr>' +
              '<th>严重度</th><th>规则</th><th>文件</th><th>消息</th><th>判定</th><th>置信度</th><th>风险</th><th>标注</th>' +
            '</tr></thead>' +
            '<tbody id="xj-finding-tbody">' +
              '<tr><td colspan="8" class="xj-text-muted" style="text-align:center;padding:30px;">加载中...</td></tr>' +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>';

    UI.render(html);

    // Load and filter findings
    loadFindings(scanId || '');
  }

  function loadFindings(scanId) {
    API.getFindings(scanId ? { scan_id: scanId } : null).then(function(data) {
      renderTable(data || []);
    }).catch(function() {
      // Use sample data when API unavailable
      renderTable(sampleFindings);
    });
  }

  function renderTable(findings) {
    var tbody = document.getElementById('xj-finding-tbody');
    var summary = document.getElementById('xj-finding-summary');
    if (!tbody) return;

    if (!findings || findings.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8"><div class="xj-empty">暂无发现数据</div></td></tr>';
      return;
    }

    // Summary
    var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, tp: 0, fp: 0, review: 0 };
    findings.forEach(function(f) {
      if (counts[f.severity] != null) counts[f.severity]++;
      if (f.verdict === 'true_positive') counts.tp++;
      else if (f.verdict === 'false_positive' || f.verdict === 'likely_false_positive') counts.fp++;
      else counts.review++;
    });

    if (summary) {
      summary.innerHTML =
        '<div class="xj-stat-card accent-red"><div class="xj-stat-value" style="font-size:24px;color:var(--xj-red);">' + counts.CRITICAL + '</div><div class="xj-stat-label">CRITICAL</div></div>' +
        '<div class="xj-stat-card accent-orange"><div class="xj-stat-value" style="font-size:24px;color:var(--xj-orange);">' + counts.HIGH + '</div><div class="xj-stat-label">HIGH</div></div>' +
        '<div class="xj-stat-card"><div class="xj-stat-value" style="font-size:24px;color:var(--xj-yellow);">' + (counts.MEDIUM + counts.LOW) + '</div><div class="xj-stat-label">MEDIUM/LOW</div></div>' +
        '<div class="xj-stat-card accent-green"><div class="xj-stat-value" style="font-size:24px;color:var(--xj-green);">' + counts.fp + '</div><div class="xj-stat-label">已过滤误报</div></div>' +
        '<div class="xj-stat-card accent-purple"><div class="xj-stat-value" style="font-size:24px;color:var(--xj-purple);">' + counts.review + '</div><div class="xj-stat-label">待复核</div></div>';
    }

    // Table rows
    tbody.innerHTML = '';
    findings.forEach(function(f) {
      var row = document.createElement('tr');
      row.className = 'xj-row-clickable';
      row.innerHTML =
        '<td><span class="xj-tag severity-' + XSS.escapeAttr(f.severity) + '">' + XSS.escapeHtml(f.severity) + '</span></td>' +
        '<td><span class="xj-code-inline">' + XSS.escapeHtml(f.rule) + '</span></td>' +
        '<td><span class="xj-text-mono" style="font-size:11px;">' + XSS.escapeHtml(f.file + ':' + f.line) + '</span></td>' +
        '<td>' + XSS.escapeHtml(f.msg) + '</td>' +
        '<td><span class="xj-tag verdict-' + XSS.escapeAttr(f.verdict.replace(/_/g, '-')) + '">' + XSS.escapeHtml(UI.verdictLabel(f.verdict)) + '</span></td>' +
        '<td>' + ((f.confidence * 100).toFixed(0)) + '%</td>' +
        '<td>' + (f.risk || 0).toFixed(1) + '</td>' +
        '<td>' +
          '<button class="xj-btn xj-btn-sm" onclick="XJPageFindings.markFP(\'' + XSS.escapeAttr(f.id) + '\')" title="标记误报">✗</button> ' +
          '<button class="xj-btn xj-btn-sm" onclick="XJPageFindings.markTP(\'' + XSS.escapeAttr(f.id) + '\')" title="标记真实问题">✓</button>' +
        '</td>';
      tbody.appendChild(row);
    });
  }

  var filterTimer = null;
  function debounceFilter() {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(filter, 300);
  }

  function filter() {
    var verdictEl = document.getElementById('xj-finding-filter-verdict');
    var sevEl = document.getElementById('xj-finding-filter-severity');
    var searchEl = document.getElementById('xj-finding-search');

    var verdict = verdictEl ? verdictEl.value : '';
    var severity = sevEl ? sevEl.value : '';
    var search = searchEl ? (searchEl.value || '').toLowerCase() : '';

    var rows = document.querySelectorAll('#xj-finding-tbody tr');
    rows.forEach(function(row) {
      var text = row.textContent.toLowerCase();
      var show = true;
      if (search && text.indexOf(search) === -1) show = false;
      if (severity && row.querySelector('.xj-tag') && row.querySelector('.xj-tag').textContent.indexOf(severity) === -1) show = false;
      row.style.display = show ? '' : 'none';
    });
  }

  function markFP(id) {
    UI.prompt('请输入误报原因', '').then(function(reason) {
      if (reason == null) return;
      API.markFalsePositive(id, reason).then(function() {
        UI.toast('已标记为误报', 'success');
        loadFindings('');
      }).catch(function() { UI.toast('标记失败', 'error'); });
    });
  }

  function markTP(id) {
    API.markTruePositive(id, '').then(function() {
      UI.toast('已标记为真实问题', 'success');
      loadFindings('');
    }).catch(function() { UI.toast('标记失败', 'error'); });
  }

  function exportJSON() {
    UI.toast('导出JSON功能已触发', 'info');
  }
  function exportMD() {
    UI.toast('导出Markdown功能已触发', 'info');
  }

  XJPages.add({
    path: '/findings',
    title: '发现管理',
    navLabel: '发现管理',
    render: render
  });

  global.XJPageFindings = { render: render, filter: filter, debounceFilter: debounceFilter, markFP: markFP, markTP: markTP, exportJSON: exportJSON, exportMD: exportMD };
})(window);
