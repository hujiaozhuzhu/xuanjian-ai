/**
 * XuanJian v3.1 - Reports Center
 * Export compliance reports, scan summaries, SARIF
 */
(function (global) {
  'use strict';

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">报表中心</h2><span class="xj-text-muted">导出合规报告、扫描摘要、SARIF格式</span></div>' +
        '</div>' +

        // Report Templates
        '<div class="xj-grid-3" style="margin-bottom:24px;">' +
          reportCard('合规报告', 'PIIPL / GDPR / ISO27001 合规审计', '📋', 'var(--xj-blue)', '/reports/compliance') +
          reportCard('扫描摘要', '含漏洞统计、趋势、修复建议', '📊', 'var(--xj-purple)', '/reports/summary') +
          reportCard('SARIF报告', '标准静态分析结果交换格式', '📄', 'var(--xj-cyan)', '/reports/sarif') +
          reportCard('攻击链报告', 'AI渗透测试完整攻击路径还原', '⚔', 'var(--xj-red)', '/reports/attack-chain') +
          reportCard('修复报告', 'PR自动修复记录与验证结果', '🔧', 'var(--xj-green)', '/reports/auto-fix') +
          reportCard('行业对标', '11个行业安全基准横向对比', '🏆', 'var(--xj-orange)', '/reports/benchmark') +
        '</div>' +

        // Scan Reports Table
        '<div class="xj-panel">' +
          '<div class="xj-panel-header">' +
            '<span class="xj-panel-title">历史扫描报告</span>' +
            '<div class="xj-btn-group">' +
              '<button class="xj-btn xj-btn-sm" onclick="XJPageReports.refreshReportList()">刷新</button>' +
            '</div>' +
          '</div>' +
          '<div class="xj-table-wrap">' +
            '<table class="xj-table">' +
              '<thead><tr><th>扫描ID</th><th>项目路径</th><th>发现数</th><th>关键/高</th><th>完成时间</th><th>操作</th></tr></thead>' +
              '<tbody id="xj-report-table-body">' +
                reportRow('scan_a1b2c3d4', '/projects/payment-svc', 28, 5, '2026-09-08 14:22') +
                reportRow('scan_e5f6g7h8', '/projects/auth-server', 42, 12, '2026-09-08 11:05') +
                reportRow('scan_i9j0k1l2', '/projects/data-pipeline', 15, 2, '2026-09-07 16:48') +
                reportRow('scan_m3n4o5p6', '/projects/mobile-api', 67, 18, '2026-09-07 09:31') +
                reportRow('scan_q7r8s9t0', '/projects/admin-panel', 23, 3, '2026-09-06 17:12') +
              '</tbody>' +
            '</table>' +
          '</div>' +
        '</div>' +

        // Compliance Summary Gauge
        '<div class="xj-grid-2">' +
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">合规评分</span></div>' +
            '<div class="xj-chart-container" id="xj-report-gauge" data-height="250"></div>' +
          '</div>' +
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">报告生成历史</span></div>' +
            '<div class="xj-timeline">' +
              '<div class="xj-timeline-item success"><div class="xj-timeline-time">10 分钟前</div><div class="xj-timeline-text">支付服务合规报告生成完成</div></div>' +
              '<div class="xj-timeline-item"><div class="xj-timeline-time">1 小时前</div><div class="xj-timeline-text">认证服务扫描摘要导出 (JSON)</div></div>' +
              '<div class="xj-timeline-item"><div class="xj-timeline-time">3 小时前</div><div class="xj-timeline-text">攻击链报告 #AT-2024-091 生成</div></div>' +
              '<div class="xj-timeline-item"><div class="xj-timeline-time">昨天</div><div class="xj-timeline-text">月度安全报告已发送给安全团队</div></div>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    setTimeout(function() {
      var container = document.getElementById('xj-report-gauge');
      if (container && typeof Charts !== 'undefined') {
        Charts.init(container, {
          series: [{ type: 'gauge', data: [{ value: 87.5, name: '合规评分' }], max: 100 }]
        });
      }
    }, 80);
  }

  function reportCard(title, desc, icon, color, path) {
    return '<div class="xj-panel" style="cursor:pointer;border-left:3px solid ' + color + ';" onclick="Router.navigate(\'' + path + '\')">' +
      '<div style="font-size:28px;margin-bottom:8px;">' + icon + '</div>' +
      '<div style="font-size:15px;font-weight:600;margin-bottom:6px;">' + XSS.escapeHtml(title) + '</div>' +
      '<div class="xj-text-muted" style="font-size:12px;">' + XSS.escapeHtml(desc) + '</div>' +
    '</div>';
  }

  function reportRow(id, path, findings, critical, time) {
    return '<tr>' +
      '<td><span class="xj-code-inline">' + XSS.escapeHtml(id) + '</span></td>' +
      '<td><span class="xj-text-mono" style="font-size:12px;">' + XSS.escapeHtml(path) + '</span></td>' +
      '<td>' + findings + '</td>' +
      '<td><span class="xj-tag severity-HIGH">' + critical + '</span></td>' +
      '<td class="xj-text-muted">' + XSS.escapeHtml(time) + '</td>' +
      '<td>' +
        '<button class="xj-btn xj-btn-sm" onclick="XJPageReports.viewReport(\'' + XSS.escapeAttr(id) + '\')">查看</button> ' +
        '<button class="xj-btn xj-btn-sm" onclick="XJPageReports.downloadReport(\'' + XSS.escapeAttr(id) + '\')">下载</button>' +
      '</td>' +
    '</tr>';
  }

  function viewReport(id) { UI.toast('查看报告: ' + id, 'info'); }
  function downloadReport(id) { UI.toast('下载报告: ' + id, 'info'); }
  function refreshReportList() { UI.toast('报告列表已刷新', 'success'); }

  XJPages.add({
    path: '/reports',
    title: '报表中心',
    navLabel: '报表中心',
    render: render
  });

  global.XJPageReports = { render: render, viewReport: viewReport, downloadReport: downloadReport, refreshReportList: refreshReportList };
})(window);
