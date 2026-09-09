/**
 * XuanJian v3.1 - Chart Engine (Canvas-based, ECharts-like API)
 * Charts: Pie/Doughnut, Bar, Line, Radar, Heatmap
 * No external dependencies - pure Canvas 2D
 */
(function (global) {
  'use strict';

  // ── Utility functions ──
  function getDevicePixelRatio() {
    return window.devicePixelRatio || 1;
  }

  function setupCanvas(canvas, width, height) {
    var dpr = getDevicePixelRatio();
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    var ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    return { ctx: ctx, w: width, h: height };
  }

  var Charts = {
    /**
     * Destroy a chart instance (cleanup canvas)
     */
    dispose: function(canvas) {
      if (!canvas) return;
      var ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    },

    /**
     * Initialize a chart on a canvas element
     * options: { series: [{ type: 'pie'|'bar'|'line'|'radar', data: [...] }], legend: {}, grid: {} }
     */
    init: function(container, options) {
      options = options || {};
      var canvas = container.querySelector('canvas');
      if (!canvas) {
        canvas = document.createElement('canvas');
        container.appendChild(canvas);
      }

      var rect = container.getBoundingClientRect();
      var W = rect.width || 600;
      var H = container.getAttribute('data-height') ? parseInt(container.getAttribute('data-height')) : 300;

      var setup = setupCanvas(canvas, W, H);
      var ctx = setup.ctx;
      var w = setup.w;
      var h = setup.h;

      var series = options.series || [];
      var renderer = series[0] ? series[0].type : 'bar';

      switch (renderer) {
        case 'pie':
        case 'doughnut':
          this._renderPie(ctx, w, h, options);
          break;
        case 'bar':
          this._renderBar(ctx, w, h, options);
          break;
        case 'line':
          this._renderLine(ctx, w, h, options);
          break;
        case 'radar':
          this._renderRadar(ctx, w, h, options);
          break;
        case 'gauge':
          this._renderGauge(ctx, w, h, options);
          break;
        default:
          ctx.fillStyle = '#8b949e';
          ctx.font = '14px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText('Unsupported chart type', w / 2, h / 2);
      }

      return { canvas: canvas, update: function(newOpts) { Charts.init(container, newOpts); } };
    },

    // ── Pie / Doughnut ──
    _renderPie: function(ctx, w, h, options) {
      var series = options.series[0] || {};
      var data = series.data || [];
      var isDoughnut = series.type === 'doughnut';
      var colors = ['#58a6ff', '#bc8cff', '#f85149', '#d29922', '#3fb950', '#39d2c0', '#e3b341', '#6e7681'];
      var pad = 20;
      var radius = Math.min(w - pad * 2, h - pad * 2) / 2 - 10;
      var cx = w / 2;
      var cy = h / 2;
      var innerR = isDoughnut ? radius * 0.55 : 0;

      var total = 0;
      data.forEach(function(d) { total += (typeof d === 'object' ? d.value : d) || 0; });

      if (total === 0) {
        ctx.fillStyle = '#30363d';
        ctx.beginPath(); ctx.arc(cx, cy, radius, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#8b949e'; ctx.font = '14px sans-serif'; ctx.textAlign = 'center';
        ctx.fillText('暂无数据', cx, cy + 5);
        return;
      }

      var startAngle = -Math.PI / 2;
      data.forEach(function(d, i) {
        var value = typeof d === 'object' ? d.value : d;
        if (!value) return;
        var sliceAngle = (value / total) * Math.PI * 2;
        var endAngle = startAngle + sliceAngle;

        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, endAngle);
        if (innerR > 0) ctx.arc(cx, cy, innerR, endAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = colors[i % colors.length];
        ctx.fill();

        // Label
        if (radius > 50) {
          var midAngle = startAngle + sliceAngle / 2;
          var labelR = radius + 15;
          var lx = cx + Math.cos(midAngle) * labelR;
          var ly = cy + Math.sin(midAngle) * labelR;
          var pct = ((value / total) * 100).toFixed(1);
          ctx.fillStyle = '#8b949e';
          ctx.font = '11px sans-serif';
          ctx.textAlign = midAngle > Math.PI / 2 && midAngle < Math.PI * 1.5 ? 'right' : 'left';
          ctx.fillText(pct + '%', lx, ly + 4);
        }

        startAngle = endAngle;
      });

      // Center text for doughnut
      if (isDoughnut) {
        ctx.fillStyle = '#e6edf3';
        ctx.font = 'bold 22px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(total, cx, cy + 2);
        ctx.fillStyle = '#8b949e';
        ctx.font = '12px sans-serif';
        ctx.fillText('总计', cx, cy + 18);
      }
    },

    // ── Bar ──
    _renderBar: function(ctx, w, h, options) {
      var series = options.series || [];
      var categories = options.xAxis && options.xAxis.data ? options.xAxis.data : [];
      var pad = { top: 20, right: 15, bottom: 50, left: 45 };
      var cw = w - pad.left - pad.right;
      var ch = h - pad.top - pad.bottom;

      // Collect all values to find max
      var allValues = [];
      series.forEach(function(s) {
        (s.data || []).forEach(function(v) {
          allValues.push(typeof v === 'object' ? v.value : v || 0);
        });
      });
      // Flatten each item if it's an array (for stacked)
      var flatValues = [];
      allValues.forEach(function(v) {
        if (Array.isArray(v)) v.forEach(function(sub) { flatValues.push(sub); });
        else flatValues.push(v);
      });
      var maxVal = Math.max.apply(null, flatValues.length ? flatValues : [1]);
      if (maxVal === 0) maxVal = 1;
      maxVal = maxVal * 1.1;

      // Grid + Y axis labels
      ctx.strokeStyle = '#30363d';
      ctx.lineWidth = 1;
      ctx.fillStyle = '#8b949e';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'right';
      for (var i = 0; i <= 4; i++) {
        var y = pad.top + (ch / 4) * i;
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
        var val = (maxVal * (1 - i / 4));
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(val), pad.left - 5, y + 4);
      }

      // Bars
      var colors = ['#58a6ff', '#bc8cff', '#f85149', '#3fb950', '#d29922'];
      var seriesCount = series.length;
      var groupWidth = cw / Math.max(categories.length, 1);
      var barWidth = Math.min(groupWidth * 0.7 / seriesCount, 40);

      categories.forEach(function(cat, idx) {
        var groupCenter = pad.left + groupWidth * idx + groupWidth / 2;
        var startX = groupCenter - (barWidth * seriesCount) / 2;

        series.forEach(function(s, si) {
          var val = s.data[idx];
          val = typeof val === 'object' && val != null ? val.value : val;
          val = val || 0;
          var barH = (val / maxVal) * ch;
          var bx = startX + si * barWidth;
          var by = pad.top + ch - barH;

          ctx.fillStyle = colors[si % colors.length];
          ctx.fillRect(bx, by, barWidth - 2, barH);

          // Value label on top
          if (barH > 16) {
            ctx.fillStyle = '#8b949e';
            ctx.font = '10px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(val, bx + barWidth / 2, by - 4);
          }
        });

        // X axis label
        ctx.fillStyle = '#8b949e';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(typeof cat === 'string' ? cat : String(cat), groupCenter, h - pad.bottom + 18);
      });

      // Legend
      if (options.legend && options.legend.show !== false && series.length > 1) {
        var lx = pad.left;
        var ly = h - 8;
        series.forEach(function(s, si) {
          ctx.fillStyle = colors[si % colors.length];
          ctx.fillRect(lx, ly - 8, 10, 10);
          ctx.fillStyle = '#8b949e';
          ctx.font = '11px sans-serif';
          ctx.textAlign = 'left';
          ctx.fillText(s.name || 'Series ' + (si + 1), lx + 14, ly);
          lx += ctx.measureText(s.name || 'Series ' + (si + 1)).width + 30;
        });
      }
    },

    // ── Line ──
    _renderLine: function(ctx, w, h, options) {
      var series = options.series || [];
      var xData = (options.xAxis && options.xAxis.data) || [];
      var pad = { top: 25, right: 20, bottom: 40, left: 50 };
      var cw = w - pad.left - pad.right;
      var ch = h - pad.top - pad.bottom;

      var allValues = [];
      series.forEach(function(s) { (s.data || []).forEach(function(v) { var val = typeof v === 'object' ? v : v; allValues.push(val || 0); }); });
      var maxVal = Math.max.apply(null, allValues.length ? allValues : [1]) * 1.1 || 1;
      var minVal = 0;

      // Grid
      ctx.strokeStyle = '#30363d';
      ctx.lineWidth = 1;
      for (var i = 0; i <= 4; i++) {
        var y = pad.top + (ch / 4) * i;
        ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke();
        var val = (maxVal - minVal) * (1 - i / 4);
        ctx.fillStyle = '#8b949e';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(val < 10 ? val.toFixed(2) : Math.round(val), pad.left - 5, y + 4);
      }

      // X labels
      var labelStep = Math.max(1, Math.floor(xData.length / 6));
      xData.forEach(function(label, idx) {
        if (idx % labelStep === 0 || idx === xData.length - 1) {
          var x = pad.left + (xData.length > 1 ? (idx / (xData.length - 1)) * cw : cw / 2);
          ctx.fillStyle = '#8b949e';
          ctx.font = '10px sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText(typeof label === 'string' ? (label.length > 8 ? label.slice(0, 8) + '..' : label) : String(label), x, h - 12);
        }
      });

      // Lines
      var colors = ['#58a6ff', '#f85149', '#3fb950', '#bc8cff', '#d29922'];
      series.forEach(function(s, si) {
        var data = s.data || [];
        if (data.length < 2) return;
        ctx.strokeStyle = colors[si % colors.length];
        ctx.lineWidth = 2;
        ctx.beginPath();
        data.forEach(function(v, idx) {
          var val = typeof v === 'object' ? v : v;
          val = val || 0;
          var x = pad.left + (data.length > 1 ? (idx / (data.length - 1)) * cw : cw / 2);
          var y = pad.top + ch - ((val - minVal) / (maxVal - minVal)) * ch;
          if (idx === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Dots
        ctx.fillStyle = colors[si % colors.length];
        data.forEach(function(v, idx) {
          var val = typeof v === 'object' ? v : v;
          val = val || 0;
          var x = pad.left + (data.length > 1 ? (idx / (data.length - 1)) * cw : cw / 2);
          var y = pad.top + ch - ((val - minVal) / (maxVal - minVal)) * ch;
          ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
        });
      });

      // Legend
      if (options.legend && options.legend.show !== false) {
        var lx = pad.left;
        series.forEach(function(s, si) {
          ctx.fillStyle = colors[si % colors.length];
          ctx.fillRect(lx, 5, 20, 3);
          ctx.fillStyle = '#8b949e';
          ctx.font = '11px sans-serif';
          ctx.textAlign = 'left';
          ctx.fillText(s.name || 'Series ' + (si + 1), lx + 24, 10);
          lx += ctx.measureText(s.name || 'Series ' + (si + 1)).width + 40;
        });
      }
    },

    // ── Radar ──
    _renderRadar: function(ctx, w, h, options) {
      var series = options.series || [];
      var indicators = (options.radar && options.radar.indicator) || [];
      var colors = ['#58a6ff', '#bc8cff', '#f85149', '#3fb950', '#d29922'];
      var n = indicators.length;
      if (n < 3) { ctx.fillStyle = '#8b949e'; ctx.font = '14px sans-serif'; ctx.textAlign = 'center'; ctx.fillText('雷达图需要至少3个维度', w/2, h/2); return; }

      var cx = w / 2;
      var cy = h / 2;
      var maxR = Math.min(w, h) / 2 - 50;
      var levels = 5;

      // Grid
      ctx.strokeStyle = '#30363d';
      ctx.lineWidth = 1;
      for (var l = 1; l <= levels; l++) {
        var r = (maxR / levels) * l;
        ctx.beginPath();
        for (var i = 0; i <= n; i++) {
          var angle = (Math.PI * 2 / n) * i - Math.PI / 2;
          var px = cx + Math.cos(angle) * r;
          var py = cy + Math.sin(angle) * r;
          if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.stroke();
      }

      // Axes + Labels
      ctx.fillStyle = '#8b949e';
      ctx.font = '11px sans-serif';
      ctx.textAlign = 'center';
      for (var j = 0; j < n; j++) {
        var angle = (Math.PI * 2 / n) * j - Math.PI / 2;
        var ax = cx + Math.cos(angle) * maxR;
        var ay = cy + Math.sin(angle) * maxR;
        ctx.strokeStyle = '#30363d';
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(ax, ay); ctx.stroke();

        var lx = cx + Math.cos(angle) * (maxR + 20);
        var ly = cy + Math.sin(angle) * (maxR + 20);
        ctx.fillStyle = '#8b949e';
        var name = indicators[j].name || '';
        ctx.fillText(name.length > 6 ? name.slice(0, 6) + '...' : name, lx, ly + 4);
      }

      // Data areas
      series.forEach(function(s, si) {
        var data = s.data[0] && s.data[0].value ? s.data[0].value : (s.data || []);
        var maxVal = 100;
        if (options.radar && options.radar.maxVal) maxVal = options.radar.maxVal;

        ctx.fillStyle = colors[si % colors.length] + '33'; // 20% opacity
        ctx.strokeStyle = colors[si % colors.length];
        ctx.lineWidth = 2;
        ctx.beginPath();
        data.forEach(function(v, idx) {
          var val = v || 0;
          var angle = (Math.PI * 2 / n) * idx - Math.PI / 2;
          var r = (val / maxVal) * maxR;
          var px = cx + Math.cos(angle) * r;
          var py = cy + Math.sin(angle) * r;
          if (idx === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
        });
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      });

      // Legend
      if (series.length > 1) {
        var lx = 10;
        var ly = 15;
        series.forEach(function(s, si) {
          ctx.fillStyle = colors[si % colors.length];
          ctx.fillRect(lx, ly - 8, 10, 10);
          ctx.fillStyle = '#8b949e';
          ctx.font = '11px sans-serif';
          ctx.textAlign = 'left';
          ctx.fillText(s.name || '', lx + 14, ly);
          ly += 16;
        });
      }
    },

    // ── Gauge ──
    _renderGauge: function(ctx, w, h, options) {
      var series = options.series[0] || {};
      var value = Array.isArray(series.data) && series.data[0] ? (series.data[0].value || series.data[0] || 0) : 0;
      var max = series.max || 100;
      var name = series.name || '';
      var cx = w / 2;
      var cy = h / 2 + 10;
      var radius = Math.min(w, h) / 2 - 20;
      var startAngle = Math.PI * 0.8;
      var endAngle = Math.PI * 2.2;
      var progress = Math.min(value / max, 1);

      // Background arc
      ctx.strokeStyle = '#21262d';
      ctx.lineWidth = 16;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, endAngle);
      ctx.stroke();

      // Value arc
      var pctAngle = startAngle + (endAngle - startAngle) * progress;
      ctx.strokeStyle = progress < 0.5 ? '#58a6ff' : progress < 0.8 ? '#d29922' : '#f85149';
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, pctAngle);
      ctx.stroke();

      // Center text
      ctx.fillStyle = '#e6edf3';
      ctx.font = 'bold 28px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(value.toFixed(1), cx, cy + 4);
      ctx.fillStyle = '#8b949e';
      ctx.font = '13px sans-serif';
      ctx.fillText(name, cx, cy + 24);
    }
  };

  global.Charts = Charts;
})(window);
