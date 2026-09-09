/**
 * XuanJian v3.1 - DevSecOps Page
 * Pipeline gate dashboard, ticket lifecycle management, webhook integration
 */
(function (global) {
  'use strict';

  var sampleTickets = [
    { id: 'T-1001', title: 'CRITICAL SQL注入在支付网关', severity: 'CRITICAL', status: 'open', assignee: '安全团队', source: 'github', created: '2026-09-08 14:22', sla: '2小时内' },
    { id: 'T-1002', title: 'HIGH XSS漏洞 - 用户Profile页面', severity: 'HIGH', status: 'in-progress', assignee: '前端团队', source: 'jira', created: '2026-09-08 11:05', sla: '24小时内' },
    { id: 'T-1003', title: 'MEDIUM 弱加密算法 - MD5密码哈希', severity: 'MEDIUM', status: 'open', assignee: '后端团队', source: 'github', created: '2026-09-08 09:31', sla: '72小时内' },
    { id: 'T-1004', title: 'HIGH 不安全反序列化 - Jackson', severity: 'HIGH', status: 'resolved', assignee: 'Java团队', source: 'jira', created: '2026-09-07 16:48', sla: '已修复' },
    { id: 'T-1005', title: 'LOW 缺少CSP安全头', severity: 'LOW', status: 'open', assignee: '运维团队', source: 'gitlab', created: '2026-09-07 09:15', sla: '7天内' }
  ];

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">DevSecOps 安全看板</h2><span class="xj-text-muted">CI/CD门禁 · 工单生命周期 · Webhook集成 · 安全度量</span></div>' +
          '<div class="xj-btn-group">' +
            '<button class="xj-btn xj-btn-primary" onclick="XJPageDevSecOps.syncFindings()">同步发现到工单</button>' +
            '<button class="xj-btn" onclick="XJPageDevSecOps.configureWebhook()">配置Webhook</button>' +
          '</div>' +
        '</div>' +

        // Stats Row
        '<div class="xj-stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:16px;">' +
          '<div class="xj-stat-card accent-red"><div class="xj-stat-value" style="color:var(--xj-red);font-size:24px;">3</div><div class="xj-stat-label">开放工单</div></div>' +
          '<div class="xj-stat-card accent-orange"><div class="xj-stat-value" style="color:var(--xj-orange);font-size:24px;">1</div><div class="xj-stat-label">处理中</div></div>' +
          '<div class="xj-stat-card accent-green"><div class="xj-stat-value" style="color:var(--xj-green);font-size:24px;">12</div><div class="xj-stat-label">本月已修复</div></div>' +
          '<div class="xj-stat-card accent-purple"><div class="xj-stat-value" style="color:var(--xj-purple);font-size:24px;">98.5%</div><div class="xj-stat-label">门禁通过率</div></div>' +
        '</div>' +

        // Pipeline Gate Dashboard
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">CI/CD 门禁看板</span></div>' +
          '<div class="xj-grid-4" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr));margin-bottom:16px;">' +
            gateCard('生产部署门禁', 'passed', '所有安全门禁通过', 'var(--xj-green)') +
            gateCard('预发环境门禁', 'passed', '扫描完成: 0 关键漏洞', 'var(--xj-green)') +
            gateCard('测试环境门禁', 'warning', '2个HIGH漏洞可放行', 'var(--xj-orange)') +
            gateCard('开发环境门禁', 'passed', '15个MEDIUM已确认', 'var(--xj-green)') +
          '</div>' +
          '<div class="xj-chart-container" id="xj-devops-chart-gate" data-height="200"></div>' +
        '</div>' +

        // Ticket Lifecycle
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">工单生命周期</span></div>' +
          '<div class="xj-table-wrap"><table class="xj-table">' +
            '<thead><tr><th>工单ID</th><th>标题</th><th>严重度</th><th>状态</th><th>负责人</th><th>来源</th><th>创建时间</th><th>SLA</th></tr></thead>' +
            '<tbody id="xj-devops-ticket-body"></tbody>' +
          '</table></div>' +
        '</div>' +

        // Webhook Integrations
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">Webhook 集成状态</span></div>' +
          '<div class="xj-grid-3" style="grid-template-columns:repeat(auto-fit,minmax(220px,1fr));">' +
            webhookCard('GitHub Actions', '已连接', 'POST /api/devops/webhook/github', '#3fb950') +
            webhookCard('GitLab CI', '已连接', 'POST /api/devops/webhook/gitlab', '#3fb950') +
            webhookCard('Jira', '未配置', 'POST /api/devops/webhook/jira', '#6e7681') +
          '</div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    setTimeout(function() {
      var container = document.getElementById('xj-devops-chart-gate');
      if (container && typeof Charts !== 'undefined') {
        Charts.init(container, {
          series: [{ type: 'bar', name: '通行次数', data: [45, 38, 12, 52] }],
          xAxis: { data: ['生产门禁', '预发门禁', '测试门禁', '开发门禁'] },
          legend: { show: false }
        });
      }
      renderTicketTable();
    }, 80);
  }

  function gateCard(title, status, desc, color) {
    var icon = status === 'passed' ? '✓' : status === 'failed' ? '✕' : '⚠';
    return '<div style="background:var(--xj-bg-0);border-radius:8px;padding:14px;border-left:3px solid ' + color + ';">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">' +
        '<span style="font-weight:600;font-size:13px;">' + XSS.escapeHtml(title) + '</span>' +
        '<span style="font-size:18px;color:' + color + ';font-weight:700;">' + icon + '</span>' +
      '</div>' +
      '<div class="xj-text-muted" style="font-size:12px;">' + XSS.escapeHtml(desc) + '</div>' +
    '</div>';
  }

  function webhookCard(name, status, endpoint, color) {
    return '<div style="background:var(--xj-bg-0);border-radius:8px;padding:14px;border:1px solid var(--xj-border);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">' +
        '<span style="font-weight:600;font-size:13px;">' + XSS.escapeHtml(name) + '</span>' +
        '<span class="xj-tag" style="background:' + color + '22;color:' + color + ';">' + XSS.escapeHtml(status) + '</span>' +
      '</div>' +
      '<div class="xj-text-mono" style="font-size:11px;color:var(--xj-text-2);background:var(--xj-bg-1);padding:6px 8px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + XSS.escapeHtml(endpoint) + '</div>' +
    '</div>';
  }

  function renderTicketTable() {
    var tbody = document.getElementById('xj-devops-ticket-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    sampleTickets.forEach(function(t) {
      var statusCls = t.status === 'open' ? 'status-open' : t.status === 'resolved' ? 'status-closed' : 'status-pending';
      var sourceIcon = t.source === 'github' ? 'GH' : t.source === 'gitlab' ? 'GL' : 'JR';
      var tr = document.createElement('tr');
      tr.className = 'xj-row-clickable';
      tr.onclick = function() { UI.toast('查看工单详情: ' + t.id, 'info'); };
      tr.innerHTML =
        '<td><span class="xj-code-inline">' + XSS.escapeHtml(t.id) + '</span></td>' +
        '<td>' + XSS.escapeHtml(t.title) + '</td>' +
        '<td><span class="xj-tag severity-' + XSS.escapeAttr(t.severity) + '">' + XSS.escapeHtml(t.severity) + '</span></td>' +
        '<td><span class="xj-tag ' + statusCls + '">' + XSS.escapeHtml(t.status) + '</span></td>' +
        '<td>' + XSS.escapeHtml(t.assignee) + '</td>' +
        '<td>' + XSS.escapeHtml(sourceIcon) + '</td>' +
        '<td class="xj-text-muted" style="font-size:12px;">' + XSS.escapeHtml(t.created) + '</td>' +
        '<td><span class="xj-text-muted" style="font-size:12px;">' + XSS.escapeHtml(t.sla) + '</span></td>';
      tbody.appendChild(tr);
    });
  }

  function syncFindings() { UI.toast('正在将安全发现同步到工单系统...', 'info'); }
  function configureWebhook() { UI.toast('打开Webhook配置面板', 'info'); }

  XJPages.add({
    path: '/devsecops',
    title: 'DevSecOps',
    navLabel: 'DevSecOps',
    render: render
  });

  global.XJPageDevSecOps = { render: render, syncFindings: syncFindings, configureWebhook: configureWebhook };
})(window);
