/**
 * XuanJian v3.1 - Auto Fix PR Page
 * Diff preview, triple verification, PR tracking
 */
(function (global) {
  'use strict';

  var samplePRs = [
    { id: 'PR-142', title: 'fix: 修复 UserDao SQL注入漏洞', file: 'src/main/dao/UserDao.java', status: 'merged', verified: true, author: 'xuanjian-bot', date: '2026-09-08' },
    { id: 'PR-143', title: 'fix: HttpResponse 添加 XSS 输出编码', file: 'src/main/web/ProfileServlet.java', status: 'open', verified: true, author: 'xuanjian-bot', date: '2026-09-08' },
    { id: 'PR-144', title: 'fix: 密码哈希升级为 BCrypt', file: 'src/main/security/AuthUtil.java', status: 'review', verified: false, author: 'xuanjian-bot', date: '2026-09-07' },
    { id: 'PR-145', title: 'fix: 移除硬编码密钥到环境变量', file: 'src/main/config/AppConfig.java', status: 'open', verified: true, author: 'xuanjian-bot', date: '2026-09-07' }
  ];

  var sampleDiff = [
    { type: 'del', code: 'String sql = "SELECT * FROM users WHERE id = " + userId;' },
    { type: 'add', code: 'String sql = "SELECT * FROM users WHERE id = ?";' },
    { type: 'ctx', code: ' PreparedStatement ps = conn.prepareStatement(sql);' },
    { type: 'add', code: ' ps.setInt(1, userId); // 参数化查询防止SQL注入' },
    { type: 'ctx', code: ' ResultSet rs = ps.executeQuery();' },
    { type: 'del', code: ' ResultSet rs = stmt.executeQuery(sql);' }
  ];

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">自动修复 PR</h2><span class="xj-text-muted">AI生成修复代码 · Diff预览 · 三重校验 · PR跟踪</span></div>' +
          '<button class="xj-btn xj-btn-primary" onclick="XJPageAutoFix.generateNewFix()">+ 生成新修复</button>' +
        '</div>' +

        // Stats
        '<div class="xj-stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:16px;">' +
          '<div class="xj-stat-card accent-green"><div class="xj-stat-value" style="color:var(--xj-green);font-size:24px;">28</div><div class="xj-stat-label">已合并PR</div></div>' +
          '<div class="xj-stat-card accent-orange"><div class="xj-stat-value" style="color:var(--xj-orange);font-size:24px;">4</div><div class="xj-stat-label">待审核PR</div></div>' +
          '<div class="xj-stat-card accent-blue"><div class="xj-stat-value" style="color:var(--xj-blue);font-size:24px;">97%</div><div class="xj-stat-label">三重校验通过率</div></div>' +
          '<div class="xj-stat-card accent-purple"><div class="xj-stat-value" style="color:var(--xj-purple);font-size:24px;">42min</div><div class="xj-stat-label">平均修复时间</div></div>' +
        '</div>' +

        '<div class="xj-grid-2">' +
          // PR List
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">PR 跟踪</span></div>' +
            '<div style="display:flex;flex-direction:column;gap:8px;">' +
              prItem(samplePRs[0]) +
              prItem(samplePRs[1]) +
              prItem(samplePRs[2]) +
              prItem(samplePRs[3]) +
            '</div>' +
          '</div>' +

          // Diff Preview
          '<div class="xj-panel">' +
            '<div class="xj-panel-header">' +
              '<span class="xj-panel-title">Diff 预览: PR-142</span>' +
              '<span class="xj-tag status-closed">已合并</span>' +
            '</div>' +
            '<div class="xj-text-mono" style="font-size:12px;margin-bottom:8px;color:var(--xj-blue);">src/main/dao/UserDao.java</div>' +
            '<div class="xj-code-diff" id="xj-autofix-diff">' +
              renderDiffLines(sampleDiff) +
            '</div>' +
          '</div>' +
        '</div>' +

        // Triple Verification
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">三重校验面板</span></div>' +
          '<div class="xj-grid-3" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr));">' +
            verifyStep('第一重: 语法校验', 'AST解析 + 编译检查', true, '通过') +
            verifyStep('第二重: 安全校验', '修复后Semgrep扫描 + 漏洞复测', true, '通过') +
            verifyStep('第三重: 功能校验', '单元测试 + 回归测试 + 集成测试', true, '通过 (14/14)') +
          '</div>' +
        '</div>' +
      '</div>';

    UI.render(html);
  }

  function prItem(pr) {
    var statusCls = pr.status === 'merged' ? 'status-closed' : pr.status === 'open' ? 'status-open' : 'status-pending';
    var verifiedIcon = pr.verified ? '✓ 已校验' : '⏳ 待校验';
    return '<div style="background:var(--xj-bg-0);border-radius:8px;padding:12px;border:1px solid var(--xj-border);cursor:pointer;" onclick="UI.toast(\'查看PR详情: ' + XSS.escapeAttr(pr.id) + '\',\'info\')">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">' +
        '<span style="font-weight:600;font-size:13px;">' + XSS.escapeHtml(pr.id + ': ' + pr.title) + '</span>' +
        '<span class="xj-tag ' + statusCls + '">' + XSS.escapeHtml(pr.status) + '</span>' +
      '</div>' +
      '<div style="font-size:11px;color:var(--xj-text-2);display:flex;align-items:center;gap:8px;">' +
        '<span>' + XSS.escapeHtml(pr.file) + '</span>' +
        '<span>|</span>' +
        '<span>' + XSS.escapeHtml(pr.author) + '</span>' +
        '<span>|</span>' +
        '<span style="color:var(--xj-green);">' + verifiedIcon + '</span>' +
      '</div>' +
    '</div>';
  }

  function renderDiffLines(lines) {
    var html = '';
    var lineNumOld = 1, lineNumNew = 1;
    lines.forEach(function(line, idx) {
      var cls = line.type === 'add' ? 'xj-diff-add' : line.type === 'del' ? 'xj-diff-del' : '';
      var sign = line.type === 'add' ? '+' : line.type === 'del' ? '-' : ' ';
      html += '<div class="diff-line ' + cls + '">' +
        '<span class="xj-diff-line-num">' + (line.type === 'add' ? '' : lineNumOld++) + '</span>' +
        '<span class="xj-diff-line-num">' + (line.type === 'del' ? '' : lineNumNew++) + '</span>' +
        '<span class="xj-diff-code">' + XSS.escapeHtml(sign + ' ' + line.code) + '</span>' +
      '</div>';
    });
    return html;
  }

  function verifyStep(title, desc, passed, result) {
    var color = passed ? 'var(--xj-green)' : 'var(--xj-red)';
    return '<div style="background:var(--xj-bg-0);border-radius:8px;padding:14px;border-left:3px solid ' + color + ';">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">' +
        '<span style="font-weight:600;font-size:13px;">' + XSS.escapeHtml(title) + '</span>' +
        '<span style="color:' + color + ';font-weight:600;font-size:12px;">' + XSS.escapeHtml(result) + '</span>' +
      '</div>' +
      '<div class="xj-text-muted" style="font-size:12px;">' + XSS.escapeHtml(desc) + '</div>' +
    '</div>';
  }

  function generateNewFix() { UI.toast('正在分析发现并生成修复方案...', 'info'); }

  XJPages.add({
    path: '/auto-fix',
    title: '自动修复PR',
    navLabel: '自动修复PR',
    render: render
  });

  global.XJPageAutoFix = { render: render, generateNewFix: generateNewFix };
})(window);
