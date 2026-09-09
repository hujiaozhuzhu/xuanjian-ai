/**
 * XuanJian v3.1 - Privacy Collaboration Page
 * Federated training monitor, compliance reports, collaborative tasks
 */
(function (global) {
  'use strict';

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">隐私计算协同</h2><span class="xj-text-muted">联邦训练监控 · 协同任务 · 合规报告 · 规则共享</span></div>' +
          '<div class="xj-btn-group">' +
            '<button class="xj-btn xj-btn-primary" onclick="XJPagePrivacy.startFederatedRound()">启动联邦训练</button>' +
          '</div>' +
        '</div>' +

        // Stats
        '<div class="xj-stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:16px;">' +
          '<div class="xj-stat-card accent-purple"><div class="xj-stat-value" style="color:var(--xj-purple);font-size:24px;">5</div><div class="xj-stat-label">联邦轮次完成</div></div>' +
          '<div class="xj-stat-card accent-blue"><div class="xj-stat-value" style="color:var(--xj-blue);font-size:24px;">3</div><div class="xj-stat-label">参与方节点</div></div>' +
          '<div class="xj-stat-card accent-green"><div class="xj-stat-value" style="color:var(--xj-green);font-size:24px;">94.2%</div><div class="xj-stat-label">模型准确率</div></div>' +
          '<div class="xj-stat-card accent-orange"><div class="xj-stat-value" style="color:var(--xj-orange);font-size:24px;">ε=1.0</div><div class="xj-stat-label">差分隐私预算</div></div>' +
        '</div>' +

        '<div class="xj-grid-2">' +
          // Federated Training Monitor
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">联邦训练实时监控</span><span class="xj-tag status-closed">运行中</span></div>' +
            '<div style="margin-bottom:12px;">' +
              '<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;"><span>训练进度 (Round 5/10)</span><span>50%</span></div>' +
              '<div style="background:var(--xj-bg-0);border-radius:6px;height:10px;overflow:hidden;"><div style="background:var(--xj-purple);height:100%;width:50%;border-radius:6px;"></div></div>' +
            '</div>' +
            '<div class="xj-chart-container" id="xj-privacy-chart-training" data-height="220"></div>' +
          '</div>' +

          // Participating Nodes
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">参与方节点状态</span></div>' +
            '<div style="display:flex;flex-direction:column;gap:8px;">' +
              federatedNode('节点A - 支付团队', '在线', '1024 条数据', 'var(--xj-green)') +
              federatedNode('节点B - 认证团队', '在线', '768 条数据', 'var(--xj-green)') +
              federatedNode('节点C - 数据团队', '在线', '512 条数据', 'var(--xj-green)') +
            '</div>' +
          '</div>' +
        '</div>' +

        // Compliance & Collaborative Tasks
        '<div class="xj-grid-2">' +
          // Compliance Reports
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">合规标准达标</span></div>' +
            '<div style="display:flex;flex-direction:column;gap:10px;">' +
              complianceItem('个人信息保护法 (PIPL)', true, 96) +
              complianceItem('数据安全法 (DSL)', true, 92) +
              complianceItem('网络安全等级保护 2.0', true, 88) +
              complianceItem('GDPR (欧盟通用数据保护)', false, 78) +
              complianceItem('ISO 27001', true, 91) +
              complianceItem('SOC 2 Type II', false, 74) +
            '</div>' +
          '</div>' +

          // Collaborative Tasks
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">协同审计任务</span></div>' +
            '<div class="xj-table-wrap"><table class="xj-table">' +
              '<thead><tr><th>任务</th><th>团队</th><th>状态</th><th>进度</th></tr></thead>' +
              '<tbody>' +
                collabTask('XSS漏洞联合分析', '前端团队', '进行中', 65) +
                collabTask('SQL注入规则共建', '后端团队', '已完成', 100) +
                collabTask('敏感数据分类标注', '安全团队', '进行中', 42) +
                collabTask('三方依赖合规审查', '供应链团队', '待启动', 0) +
              '</tbody>' +
            '</table></div>' +
          '</div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    setTimeout(function() {
      var container = document.getElementById('xj-privacy-chart-training');
      if (container && typeof Charts !== 'undefined') {
        Charts.init(container, {
          series: [{ type: 'line', name: '准确率', data: [78, 82, 87, 91, 94.2] }],
          xAxis: { data: ['R1', 'R2', 'R3', 'R4', 'R5'] }
        });
      }
    }, 80);
  }

  function federatedNode(name, status, data, color) {
    return '<div style="background:var(--xj-bg-0);border-radius:6px;padding:10px;display:flex;align-items:center;justify-content:space-between;">' +
      '<div><div style="font-size:13px;font-weight:500;">' + XSS.escapeHtml(name) + '</div><div class="xj-text-muted" style="font-size:11px;">' + XSS.escapeHtml(data) + '</div></div>' +
      '<span class="xj-tag" style="background:' + color + '22;color:' + color + ';">' + XSS.escapeHtml(status) + '</span>' +
    '</div>';
  }

  function complianceItem(name, passed, score) {
    var icon = passed ? '✓' : '!';
    var color = passed ? 'var(--xj-green)' : 'var(--xj-orange)';
    return '<div style="display:flex;align-items:center;justify-content:space-between;">' +
      '<span style="font-size:13px;">' + XSS.escapeHtml(name) + '</span>' +
      '<div style="display:flex;align-items:center;gap:8px;">' +
        '<span style="font-size:12px;font-weight:600;color:' + color + ';">' + score + '%</span>' +
        '<span style="color:' + color + ';font-weight:600;">' + icon + '</span>' +
      '</div>' +
    '</div>';
  }

  function collabTask(task, team, status, progress) {
    var statusCls = status === '已完成' ? 'status-closed' : status === '进行中' ? 'status-open' : 'status-pending';
    var barColor = progress >= 80 ? 'var(--xj-green)' : progress > 0 ? 'var(--xj-blue)' : 'var(--xj-gray)';
    return '<tr>' +
      '<td>' + XSS.escapeHtml(task) + '</td>' +
      '<td class="xj-text-muted">' + XSS.escapeHtml(team) + '</td>' +
      '<td><span class="xj-tag ' + statusCls + '">' + XSS.escapeHtml(status) + '</span></td>' +
      '<td><div style="display:flex;align-items:center;gap:6px;"><div style="background:var(--xj-bg-0);border-radius:4px;height:6px;width:60px;overflow:hidden;"><div style="background:' + barColor + ';height:100%;width:' + progress + '%;"></div></div><span class="xj-text-muted" style="font-size:11px;">' + progress + '%</span></div></td>' +
    '</tr>';
  }

  function startFederatedRound() { UI.toast('联邦训练第6轮启动中...', 'info'); }

  XJPages.add({
    path: '/privacy',
    title: '隐私计算协同',
    navLabel: '隐私协同',
    render: render
  });

  global.XJPagePrivacy = { render: render, startFederatedRound: startFederatedRound };
})(window);
