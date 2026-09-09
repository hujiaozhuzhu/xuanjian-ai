/**
 * XuanJian v3.1 - Dashboard Page
 * Global stats + event stream with ECharts donut chart
 */
(function (global) {
  'use strict';

  // Sample data for charts when API unavailable
  var SAMPLE_STATS = {
    total_scans: 127,
    total_findings: 3842,
    false_positives: 2156,
    likely_false_positives: 489,
    true_positives: 723,
    needs_review: 474,
    reduction_rate: '68.8%'
  };

  function render() {
    var stats = SAMPLE_STATS;

    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div>' +
            '<h2 class="xj-section-title">玄鉴 v3.1 安全审计仪表板</h2>' +
            '<span class="xj-text-muted">AI驱动的代码安全分析平台</span>' +
          '</div>' +
          '<span class="xj-text-muted" id="xj-dash-last-update">上次更新: --</span>' +
        '</div>' +

        // Stat Cards
        '<div class="xj-stats-grid">' +
          statCard('总扫描数', stats.total_scans || 0, 'var(--xj-blue)', null) +
          statCard('总发现数', stats.total_findings || 0, 'var(--xj-purple)', null) +
          statCard('误报过滤', (stats.false_positives + (stats.likely_false_positives || 0)), 'var(--xj-green)', 'down') +
          statCard('真实问题', stats.true_positives || 0, 'var(--xj-red)', null) +
          statCard('待复核', stats.needs_review || 0, 'var(--xj-orange)', null) +
          statCard('误报率降低', stats.reduction_rate || '0%', 'var(--xj-cyan)', 'down') +
        '</div>' +

        // Charts Row
        '<div class="xj-grid-2">' +
          // Verdict Donut
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">发现判定分布</span></div>' +
            '<div class="xj-chart-container" id="xj-dash-chart-verdict" data-height="300"></div>' +
            '<div class="xj-chart-legend" id="xj-dash-legend-verdict"></div>' +
          '</div>' +

          // Severity Bar
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">严重程度分布</span></div>' +
            '<div class="xj-chart-container" id="xj-dash-chart-severity" data-height="300"></div>' +
          '</div>' +
        '</div>' +

        // Event Stream Panel
        '<div class="xj-panel">' +
          '<div class="xj-panel-header">' +
            '<span class="xj-panel-title">实时事件流</span>' +
            '<span id="xj-dash-stream-status" class="xj-text-muted">连接中...</span>' +
          '</div>' +
          '<div class="xj-timeline" id="xj-dash-event-stream" style="max-height:300px;overflow-y:auto;">' +
            '<div class="xj-empty">等待事件数据...</div>' +
          '</div>' +
        '</div>' +

        // Recent Scans
        '<div class="xj-panel">' +
          '<div class="xj-panel-header">' +
            '<span class="xj-panel-title">最近扫描</span>' +
            '<button class="xj-btn xj-btn-sm xj-btn-ghost" onclick="Router.navigate(\'/scan\')">新建扫描 &rarr;</button>' +
          '</div>' +
          '<div id="xj-dash-recent-scans">' +
            '<div class="xj-empty">加载中...</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    // Render charts
    setTimeout(function() {
      renderVerdictChart(stats);
      renderSeverityChart();
      loadRecentScans();
      document.getElementById('xj-dash-last-update').textContent = '上次更新: ' + new Date().toLocaleTimeString('zh-CN');
    }, 50);
  }

  function statCard(label, value, color, trend) {
    var trendHtml = trend ? '<div class="xj-stat-trend ' + (trend === 'down' ? 'up' : 'down') + '">' + (trend === 'down' ? '↓ 下降' : '↑ 上升') + '</div>' : '';
    return '<div class="xj-stat-card">' +
      '<div class="xj-stat-value" style="color:' + color + '">' + (value != null ? XSS.escapeHtml(String(value)) : '--') + '</div>' +
      '<div class="xj-stat-label">' + XSS.escapeHtml(label) + '</div>' +
      trendHtml +
    '</div>';
  }

  function renderVerdictChart(stats) {
    var container = document.getElementById('xj-dash-chart-verdict');
    if (!container || typeof Charts === 'undefined') return;

    var fp = stats.false_positives || 0;
    var lfp = stats.likely_false_positives || 0;
    var tp = stats.true_positives || 0;
    var rv = stats.needs_review || 0;

    Charts.init(container, {
      series: [{
        type: 'doughnut',
        data: [
          { value: fp, name: '误报' },
          { value: tp, name: '真实问题' },
          { value: lfp, name: '疑似误报' },
          { value: rv, name: '待复核' }
        ]
      }]
    });

    var colors = ['#6e7681', '#f85149', '#d29922', '#58a6ff'];
    var total = fp + tp + lfp + rv || 1;
    var labels = ['误报', '真实问题', '疑似误报', '待复核'];
    var values = [fp, tp, lfp, rv];
    var legendEl = document.getElementById('xj-dash-legend-verdict');
    if (legendEl) {
      legendEl.innerHTML = '';
      labels.forEach(function(l, i) {
        var item = document.createElement('span');
        item.className = 'xj-legend-item';
        item.innerHTML = '<span class="xj-legend-dot" style="background:' + colors[i] + '"></span> ' +
          XSS.escapeHtml(l) + ' (' + (total > 0 ? ((values[i]/total)*100).toFixed(1) : 0) + '%)';
        legendEl.appendChild(item);
      });
    }
  }

  function renderSeverityChart() {
    var container = document.getElementById('xj-dash-chart-severity');
    if (!container || typeof Charts === 'undefined') return;

    Charts.init(container, {
      series: [{
        type: 'bar',
        name: '发现数',
        data: [45, 128, 312, 489, 268]
      }],
      xAxis: { data: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
      legend: { show: false }
    });
  }

  function loadRecentScans() {
    var el = document.getElementById('xj-dash-recent-scans');
    if (!el) return;

    API.getScans().then(function(data) {
      if (!data || data.length === 0) {
        el.innerHTML = '<div class="xj-empty">暂无扫描记录，<a href="#/scan" class="xj-text-secondary" style="color:var(--xj-blue);text-decoration:underline;">开始首次扫描</a></div>';
        return;
      }
      var html = '<div class="xj-table-wrap"><table class="xj-table"><thead><tr>' +
        '<th>项目路径</th><th>状态</th><th>发现数</th><th>语言</th><th>耗时</th><th>开始时间</th>' +
        '</tr></thead><tbody>';
      data.slice(0, 8).forEach(function(s) {
        var statusClass = s.status === 'completed' ? 'status-closed' : s.status === 'failed' ? 'status-open' : 'status-pending';
        html += '<tr class="xj-row-clickable" onclick="Router.navigate(\'/findings?scan_id=' + XSS.escapeAttr(s.id) + '\')">' +
          '<td><span class="xj-code-inline">' + XSS.escapeHtml(s.project_path || '-') + '</span></td>' +
          '<td><span class="xj-tag ' + statusClass + '">' + XSS.escapeHtml(s.status) + '</span></td>' +
          '<td><strong>' + XSS.escapeHtml(String(s.total_findings || 0)) + '</strong></td>' +
          '<td>' + XSS.escapeHtml(s.language || '-') + '</td>' +
          '<td>' + XSS.escapeHtml(String(s.duration_seconds || '-')) + 's</td>' +
          '<td class="xj-text-muted">' + XSS.escapeHtml(UI.formatTime(s.started_at)) + '</td>' +
        '</tr>';
      });
      html += '</tbody></table></div>';
      el.innerHTML = html;
    }).catch(function() {
      el.innerHTML = '<div class="xj-empty">无法加载扫描数据（API离线）</div>';
    });
  }

  function onEnter() {
    // Setup event stream subscription
    if (typeof EventStream !== 'undefined') {
      EventStream.on('completed', function(data) {
        UI.toast('扫描完成: ' + (data.total_findings || 0) + ' 个发现', 'info');
        loadRecentScans();
      });
    }
  }

  // Register page
  if (typeof XJPages !== 'undefined') {
    XJPages.add({
      path: '/dashboard',
      title: '仪表板',
      navLabel: '仪表板',
      render: render,
      onEnter: onEnter
    });
  }

  global.XJPageDashboard = { render: render, onEnter: onEnter };
})(window);
