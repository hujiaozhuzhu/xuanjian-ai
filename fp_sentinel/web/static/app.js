/**
 * 玄鉴 XuanJian - 前端交互逻辑
 */

const API = '';
let currentScanId = null;
let ws = null;

// ─────── 初始化 ───────

document.addEventListener('DOMContentLoaded', () => {
  loadStats();
});

// ─────── 统计加载 ───────

async function loadStats() {
  try {
    const r = await fetch(API + '/api/stats');
    if (!r.ok) return;
    const d = await r.json();
    setText('s-total', d.total_findings || 0);
    setText('s-fp', d.false_positives || 0);
    setText('s-lfp', d.likely_false_positives || 0);
    setText('s-tp', d.true_positives || 0);
    setText('s-review', d.needs_review || 0);
    setText('s-rate', d.reduction_rate || '0%');
  } catch (e) {
    console.warn('加载统计失败:', e);
  }
}

// ─────── 扫描 ───────

async function startScan() {
  const pathInput = document.getElementById('project-path');
  const path = pathInput.value.trim();
  if (!path) {
    pathInput.focus();
    showStatus('请输入项目路径', 'error');
    return;
  }

  const language = document.getElementById('language').value;

  // 收集选中的扫描器
  const scannerCheckboxes = document.querySelectorAll('.checkbox-group input[type="checkbox"]:checked');
  const scanners = Array.from(scannerCheckboxes).map(cb => cb.value);

  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  btn.textContent = '扫描中...';

  const progressBar = document.getElementById('progress-bar');
  const progressFill = document.getElementById('progress-fill');
  progressBar.style.display = 'block';
  progressFill.style.width = '10%';

  showStatus('正在执行扫描...', 'info');

  try {
    const r = await fetch(API + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_path: path,
        language: language,
        scanners: scanners.length > 0 ? scanners : null,
      }),
    });

    if (!r.ok) {
      const err = await r.json();
      throw new Error(err.detail || '扫描请求失败');
    }

    const d = await r.json();
    currentScanId = d.scan_id;

    progressFill.style.width = '100%';
    showStatus(
      `扫描完成！共 ${d.total_findings} 个发现，耗时 ${d.duration_seconds}s`,
      'success'
    );

    document.getElementById('btn-export').disabled = false;

    // 加载数据
    loadStats();
    loadFindings();

    // 连接 WebSocket 监听后续进度（如果有）
    if (d.scan_id) {
      connectWS(d.scan_id);
    }

  } catch (e) {
    showStatus('扫描失败: ' + e.message, 'error');
    progressFill.style.width = '0%';
  } finally {
    btn.disabled = false;
    btn.textContent = '开始扫描';
    setTimeout(() => { progressBar.style.display = 'none'; }, 3000);
  }
}

// ─────── WebSocket ───────

function connectWS(scanId) {
  if (ws) {
    ws.close();
  }

  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${location.host}/ws/scan/${scanId}`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setStatusDot('connected');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWSMessage(data);
      } catch (e) {
        console.warn('WS消息解析失败:', e);
      }
    };

    ws.onclose = () => {
      setStatusDot('disconnected');
    };

    ws.onerror = () => {
      setStatusDot('disconnected');
    };
  } catch (e) {
    console.warn('WebSocket连接失败:', e);
  }
}

function handleWSMessage(data) {
  switch (data.type) {
    case 'progress':
      const fill = document.getElementById('progress-fill');
      if (fill) fill.style.width = data.progress + '%';
      if (data.phase) showStatus(`扫描进度: ${data.phase}`, 'info');
      break;
    case 'completed':
      showStatus('扫描已完成', 'success');
      loadStats();
      loadFindings();
      break;
    case 'error':
      showStatus('扫描出错: ' + data.error, 'error');
      break;
  }
}

// ─────── 发现列表 ───────

async function loadFindings() {
  const verdict = document.getElementById('filter-verdict').value;
  const severity = document.getElementById('filter-severity').value;

  let url = API + '/api/findings';
  const params = [];
  if (currentScanId) params.push('scan_id=' + encodeURIComponent(currentScanId));
  if (verdict) params.push('verdict=' + encodeURIComponent(verdict));
  if (severity) params.push('severity=' + encodeURIComponent(severity));
  if (params.length > 0) url += '?' + params.join('&');

  try {
    const r = await fetch(url);
    if (!r.ok) return;
    const data = await r.json();

    const tbody = document.getElementById('findings-tbody');
    const countEl = document.getElementById('result-count');
    countEl.textContent = `${data.length} 条结果`;

    if (data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">暂无匹配数据</td></tr>';
      return;
    }

    tbody.innerHTML = data.map(f => {
      const o = f.original;
      const sevBadge = `<span class="badge badge-${o.severity.toLowerCase()}">${o.severity}</span>`;
      const vp = verdictClass(f.verdict);
      const vl = verdictLabel(f.verdict);
      const vBadge = `<span class="badge badge-${vp}">${vl}</span>`;

      return `<tr onclick="showDetail('${f.id}')" style="cursor:pointer">
        <td>${sevBadge}</td>
        <td>${escapeHtml(o.rule_id)}</td>
        <td><code>${escapeHtml(o.file)}:${o.line}</code></td>
        <td>${o.line}</td>
        <td>${vBadge}</td>
        <td>${(f.confidence * 100).toFixed(0)}%</td>
        <td>${f.risk_score.toFixed(1)}</td>
        <td>
          <button class="small" onclick="event.stopPropagation(); markFP('${f.id}')">标记误报</button>
        </td>
      </tr>`;
    }).join('');

  } catch (e) {
    console.warn('加载发现列表失败:', e);
  }
}

// ─────── 发现详情 ───────

async function showDetail(findingId) {
  try {
    const r = await fetch(API + '/api/findings/' + findingId);
    if (!r.ok) return;
    const f = await r.json();
    const o = f.original;

    const body = document.getElementById('modal-body');
    body.innerHTML = `
      <div class="detail-row">
        <span class="detail-label">规则ID</span>
        <span class="detail-value">${escapeHtml(o.rule_id)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">严重程度</span>
        <span class="detail-value"><span class="badge badge-${o.severity.toLowerCase()}">${o.severity}</span></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">文件</span>
        <span class="detail-value"><code>${escapeHtml(o.file)}:${o.line}</code></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">扫描器</span>
        <span class="detail-value">${escapeHtml(o.tool)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">CWE</span>
        <span class="detail-value">${o.cwe || '-'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">OWASP</span>
        <span class="detail-value">${o.owasp || '-'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">消息</span>
        <span class="detail-value">${escapeHtml(o.message)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">代码片段</span>
      </div>
      <div class="detail-code">${escapeHtml(o.code)}</div>
      <hr style="border-color:var(--border);margin:16px 0">
      <div class="detail-row">
        <span class="detail-label">判定</span>
        <span class="detail-value"><span class="badge badge-${verdictClass(f.verdict)}">${verdictLabel(f.verdict)}</span></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">置信度</span>
        <span class="detail-value">${(f.confidence * 100).toFixed(1)}%</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">风险评分</span>
        <span class="detail-value">${f.risk_score.toFixed(1)} / 10</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">建议</span>
        <span class="detail-value">${escapeHtml(f.recommendation)}</span>
      </div>
      ${f.filter_reasons && f.filter_reasons.length > 0 ? `
        <div class="detail-row">
          <span class="detail-label">过滤原因</span>
        </div>
        ${f.filter_reasons.map(r => `
          <div class="reason-item">
            <span class="reason-level">[${r.filter_level}]</span>
            <strong>${escapeHtml(r.rule_name)}</strong>: ${escapeHtml(r.description)}
            <span style="color:var(--text-secondary);margin-left:8px">(${(r.confidence * 100).toFixed(0)}%)</span>
          </div>
        `).join('')}
      ` : ''}
    `;

    document.getElementById('modal-title').textContent = `发现详情 - ${o.rule_id}`;
    document.getElementById('modal-overlay').style.display = 'flex';

  } catch (e) {
    console.warn('加载详情失败:', e);
  }
}

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
}

// ─────── 标记误报 ───────

async function markFP(findingId) {
  const reason = prompt('请输入误报原因:');
  if (!reason) return;

  try {
    const r = await fetch(API + `/api/findings/${findingId}/mark-fp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: reason, scope: 'instance' }),
    });

    if (r.ok) {
      showStatus('已标记为误报', 'success');
      loadStats();
      loadFindings();
    } else {
      showStatus('标记失败', 'error');
    }
  } catch (e) {
    showStatus('标记失败: ' + e.message, 'error');
  }
}

// ─────── 导出报告 ───────

async function exportReport() {
  if (!currentScanId) {
    showStatus('请先执行扫描', 'error');
    return;
  }

  const format = prompt('选择导出格式 (json/markdown):', 'json');
  if (!format) return;

  try {
    // 使用后端 export 端点（复用 list_findings + 计算）
    const r = await fetch(API + `/api/findings?scan_id=${currentScanId}`);
    const findings = await r.json();

    const report = {
      scan_id: currentScanId,
      exported_at: new Date().toISOString(),
      total_findings: findings.length,
      findings: findings,
    };

    const blob = new Blob(
      [JSON.stringify(report, null, 2)],
      { type: 'application/json' }
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xuanjian-report-${currentScanId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    showStatus('报告已导出', 'success');
  } catch (e) {
    showStatus('导出失败: ' + e.message, 'error');
  }
}

// ─────── 工具函数 ───────

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function showStatus(msg, type) {
  const el = document.getElementById('scan-status');
  el.textContent = msg;
  el.style.color = type === 'error' ? 'var(--accent-red)' :
                   type === 'success' ? 'var(--accent-green)' :
                   'var(--text-secondary)';
}

function setStatusDot(state) {
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('connection-status');
  switch (state) {
    case 'connected':
      dot.style.background = 'var(--accent-green)';
      label.textContent = '已连接';
      break;
    case 'disconnected':
      dot.style.background = 'var(--accent-gray)';
      label.textContent = '已断开';
      break;
  }
}

function verdictClass(v) {
  return {
    false_positive: 'fp',
    likely_false_positive: 'lfp',
    true_positive: 'tp',
    needs_review: 'review',
  }[v] || 'review';
}

function verdictLabel(v) {
  return {
    false_positive: '误报',
    likely_false_positive: '疑似误报',
    true_positive: '真实问题',
    needs_review: '待复核',
  }[v] || v;
}

function escapeHtml(s) {
  if (!s) return '';
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// ESC 关闭模态
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});
