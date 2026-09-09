/**
 * XuanJian v3.1 - Industry Benchmark Page
 * Radar chart comparison, 11 industry vertical benchmarks
 */
(function (global) {
  'use strict';

  var industries = [
    { id: 'finance', name: '金融', score: 92, vulnCount: 156, critical: 8 },
    { id: 'healthcare', name: '医疗', score: 88, vulnCount: 203, critical: 12 },
    { id: 'ecommerce', name: '电商', score: 85, vulnCount: 489, critical: 15 },
    { id: 'gaming', name: '游戏', score: 72, vulnCount: 678, critical: 32 },
    { id: 'education', name: '教育', score: 79, vulnCount: 321, critical: 18 },
    { id: 'government', name: '政务', score: 91, vulnCount: 134, critical: 5 },
    { id: 'telecom', name: '电信', score: 87, vulnCount: 267, critical: 11 },
    { id: 'automotive', name: '汽车', score: 74, vulnCount: 534, critical: 28 },
    { id: 'logistics', name: '物流', score: 81, vulnCount: 398, critical: 22 },
    { id: 'media', name: '媒体', score: 76, vulnCount: 445, critical: 25 },
    { id: 'manufacturing', name: '制造业', score: 69, vulnCount: 612, critical: 38 }
  ];

  var radarIndicators = [
    { name: '代码规范', max: 100 },
    { name: '漏洞修复率', max: 100 },
    { name: '安全测试覆盖率', max: 100 },
    { name: '依赖更新及时性', max: 100 },
    { name: '合规达标率', max: 100 },
    { name: '响应速度', max: 100 }
  ];

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">行业基准对标</h2><span class="xj-text-muted">雷达图可视化 · 11个行业安全基准 · 横向对比分析</span></div>' +
          '<button class="xj-btn xj-btn-primary" onclick="XJPageBenchmark.refreshBenchmark()">刷新基准数据</button>' +
        '</div>' +

        // Radar Chart + Industry List
        '<div class="xj-grid-2">' +
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">安全能力雷达图 (6维度评估)</span></div>' +
            '<div class="xj-chart-container" id="xj-benchmark-radar" data-height="380"></div>' +
          '</div>' +
          '<div class="xj-panel">' +
            '<div class="xj-panel-header"><span class="xj-panel-title">行业安全评分概述</span></div>' +
            '<div style="display:flex;flex-direction:column;gap:10px;" id="xj-benchmark-industry-cards">' +
              industryCard('你的项目', '项目本身', 84, 267, 11, true) +
              industryCard('行业平均', '全行业均值', 80, 395, 18, false) +
              industryCard('Top基准', '金融/政务', 92, 134, 5, false) +
              industryCard('待改进', '制造业/汽车', 71, 573, 33, false) +
            '</div>' +
          '</div>' +
        '</div>' +

        // Bar Chart - Industry Comparison
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">11行业安全评分对比</span></div>' +
          '<div class="xj-chart-container" id="xj-benchmark-bar" data-height="300"></div>' +
        '</div>' +

        // Industry Detail Table
        '<div class="xj-panel">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">行业详细对照表</span></div>' +
          '<div class="xj-table-wrap"><table class="xj-table">' +
            '<thead><tr><th>行业</th><th>安全评分</th><th>漏洞总数</th><th>关键漏洞</th><th>您的差距</th><th>建议优先级</th></tr></thead>' +
            '<tbody id="xj-benchmark-table-body"></tbody>' +
          '</table></div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    setTimeout(function() {
      renderRadarChart();
      renderBarChart();
      renderIndustryTable();
    }, 80);
  }

  function renderRadarChart() {
    var container = document.getElementById('xj-benchmark-radar');
    if (!container || typeof Charts === 'undefined') return;
    Charts.init(container, {
      series: [
        { type: 'radar', name: '你的项目', data: [{ value: [84, 78, 91, 72, 88, 85] }] },
        { type: 'radar', name: '行业Top', data: [{ value: [95, 92, 96, 88, 94, 90] }] },
        { type: 'radar', name: '行业均值', data: [{ value: [76, 72, 68, 65, 74, 71] }] }
      ],
      radar: { indicator: radarIndicators, maxVal: 100 }
    });
  }

  function renderBarChart() {
    var container = document.getElementById('xj-benchmark-bar');
    if (!container || typeof Charts === 'undefined') return;
    var categories = industries.map(function(i) { return i.name; });
    var scores = industries.map(function(i) { return i.score; });
    Charts.init(container, {
      series: [{ type: 'bar', name: '安全评分', data: scores }],
      xAxis: { data: categories },
      legend: { show: false }
    });
  }

  function renderIndustryTable() {
    var tbody = document.getElementById('xj-benchmark-table-body');
    if (!tbody) return;
    var myScore = 84;
    tbody.innerHTML = '';
    industries.forEach(function(ind) {
      var diff = myScore - ind.score;
      var diffStr = diff > 0 ? '+' + diff + ' (领先)' : diff + ' (落后)';
      var diffColor = diff > 0 ? 'var(--xj-green)' : 'var(--xj-red)';
      var priority = ind.critical > 20 ? 'severity-CRITICAL' : ind.critical > 10 ? 'severity-HIGH' : 'severity-MEDIUM';
      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td><strong>' + XSS.escapeHtml(ind.name) + '</strong></td>' +
        '<td><span style="color:' + (ind.score >= 85 ? 'var(--xj-green)' : ind.score >= 75 ? 'var(--xj-orange)' : 'var(--xj-red)') + ';font-weight:600;">' + ind.score + '</span></td>' +
        '<td>' + ind.vulnCount + '</td>' +
        '<td><span class="xj-tag severity-' + (ind.critical > 20 ? 'CRITICAL' : ind.critical > 10 ? 'HIGH' : 'MEDIUM') + '">' + ind.critical + '</span></td>' +
        '<td><span style="color:' + diffColor + ';">' + XSS.escapeHtml(diffStr) + '</span></td>' +
        '<td><span class="xj-tag ' + priority + '">' + (ind.critical > 20 ? 'P0' : ind.critical > 10 ? 'P1' : 'P2') + '</span></td>';
      tbody.appendChild(tr);
    });
  }

  function industryCard(label, sublabel, score, vulns, critical, isHighlight) {
    var borderColor = isHighlight ? 'var(--xj-blue)' : 'var(--xj-border)';
    return '<div style="background:' + (isHighlight ? 'var(--xj-blue-dim)' : 'var(--xj-bg-0)') + ';border-radius:8px;padding:14px;border-left:3px solid ' + borderColor + ';">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;">' +
        '<div><div style="font-weight:600;font-size:14px;">' + XSS.escapeHtml(label) + '</div><div class="xj-text-muted" style="font-size:11px;">' + XSS.escapeHtml(sublabel) + '</div></div>' +
        '<div style="text-align:right;"><div style="font-size:24px;font-weight:700;color:' + (score >= 85 ? 'var(--xj-green)' : 'var(--xj-orange)') + ';">' + score + '</div><div class="xj-text-muted" style="font-size:11px;">' + vulns + ' 漏洞 · ' + critical + ' 关键</div></div>' +
      '</div>' +
    '</div>';
  }

  function refreshBenchmark() { UI.toast('正在更新行业基准数据...', 'info'); }

  XJPages.add({
    path: '/benchmark',
    title: '行业基准对标',
    navLabel: '行业基准',
    render: render
  });

  global.XJPageBenchmark = { render: render, refreshBenchmark: refreshBenchmark };
})(window);
