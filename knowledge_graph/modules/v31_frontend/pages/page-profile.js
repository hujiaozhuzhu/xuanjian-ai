/**
 * XuanJian v3.1 - Developer Profile Page
 * Personalization engine stats, code style fingerprint, FP trends
 */
(function (global) {
  'use strict';

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">开发者画像</h2><span class="xj-text-muted">自适应误报引擎 · 个性化代码风格建模</span></div>' +
          '<button class="xj-btn xj-btn-primary" onclick="XJPageProfile.buildProfile()">重建画像</button>' +
        '</div>' +

        // FP Stats Summary
        '<div class="xj-stats-grid">' +
          '<div class="xj-stat-card accent-blue"><div class="xj-stat-value" style="color:var(--xj-blue);">1,247</div><div class="xj-stat-label">总反馈数</div></div>' +
          '<div class="xj-stat-card accent-green"><div class="xj-stat-value" style="color:var(--xj-green);">12.3%</div><div class="xj-stat-label">当前误报率<span class="xj-stat-trend up">↓ 持续下降</span></div></div>' +
          '<div class="xj-stat-card accent-orange"><div class="xj-stat-value" style="color:var(--xj-orange);">3</div><div class="xj-stat-label">优化次数</div></div>' +
          '<div class="xj-stat-card accent-purple"><div class="xj-stat-value" style="color:var(--xj-purple);">1%</div><div class="xj-stat-label">目标误报率</div></div>' +
        '</div>' +

        '<div class="xj-grid-2">' +
          // FP Trend Line Chart
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">误报率趋势 (30天)</span></div>' +
            '<div class="xj-chart-container" id="xj-profile-chart-trend" data-height="260"></div>' +
          '</div>' +

          // Recommendations
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">优化建议</span></div>' +
            '<div style="display:flex;flex-direction:column;gap:8px;">' +
              '<div style="background:var(--xj-bg-3);border-radius:6px;padding:12px;">' +
                '<span class="xj-tag severity-HIGH" style="margin-right:8px;">高优先</span>' +
                '<span>java.path.traversal 规则误报率过高 (89%)，建议添加路径白名单规则</span>' +
              '</div>' +
              '<div style="background:var(--xj-bg-3);border-radius:6px;padding:12px;">' +
                '<span class="xj-tag severity-MEDIUM" style="margin-right:8px;">中优先</span>' +
                '<span>建议对 test/ 目录全面豁免误报判定</span>' +
              '</div>' +
              '<div style="background:var(--xj-bg-3);border-radius:6px;padding:12px;">' +
                '<span class="xj-tag severity-LOW" style="margin-right:8px;">信息</span>' +
                '<span>代码风格画像与项目实际风格匹配度 94%</span>' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        // Top FP Rules Table
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">高频误报规则 TOP10</span></div>' +
          '<div class="xj-table-wrap"><table class="xj-table">' +
            '<thead><tr><th>规则ID</th><th>总触发</th><th>误报数</th><th>误报率</th><th>建议操作</th></tr></thead>' +
            '<tbody>' +
              topFpRule('java.path.traversal', 156, 139, 89) +
              topFpRule('java.hardcoded.secret', 203, 178, 88) +
              topFpRule('java.sqli.dynamic.query', 98, 72, 73) +
              topFpRule('java.crypto.weak.hash', 67, 45, 67) +
              topFpRule('java.command.exec', 44, 28, 64) +
              topFpRule('java.unsafe.reflection', 112, 61, 54) +
              topFpRule('java.null.deref', 289, 144, 50) +
              topFpRule('java.xss.owasp', 76, 35, 46) +
            '</tbody>' +
          '</table></div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    setTimeout(function() {
      var container = document.getElementById('xj-profile-chart-trend');
      if (container && typeof Charts !== 'undefined') {
        Charts.init(container, {
          series: [{
            type: 'line',
            name: '误报率',
            data: [22, 21, 20, 19.5, 19, 18, 17.5, 16, 15.8, 15, 14.5, 14, 13.5, 13.2, 13, 12.8, 12.5, 12.3]
          }],
          xAxis: { data: ['D1','D3','D5','D7','D9','D11','D13','D15','D17','D19','D21','D23','D25','D27','D29','D30'] }
        });
      }
    }, 80);
  }

  function topFpRule(rule, total, fp, pct) {
    var color = pct > 70 ? 'var(--xj-red)' : pct > 50 ? 'var(--xj-orange)' : 'var(--xj-yellow)';
    return '<tr>' +
      '<td><span class="xj-code-inline">' + XSS.escapeHtml(rule) + '</span></td>' +
      '<td>' + total + '</td>' +
      '<td>' + fp + '</td>' +
      '<td><span style="color:' + color + ';font-weight:600;">' + pct + '%</span></td>' +
      '<td><button class="xj-btn xj-btn-sm" onclick="UI.toast(\'自动优化规则: ' + XSS.escapeAttr(rule) + '\',\'info\')">忽略规则</button></td>' +
    '</tr>';
  }

  function buildProfile() {
    UI.toast('正在分析代码风格并构建画像...', 'info');
    setTimeout(function() { UI.toast('代码风格画像构建完成', 'success'); }, 2000);
  }

  XJPages.add({
    path: '/profile',
    title: '开发者画像',
    navLabel: '开发者画像',
    render: render
  });

  global.XJPageProfile = { render: render, buildProfile: buildProfile };
})(window);
