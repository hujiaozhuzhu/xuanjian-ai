/**
 * 玄鉴 XuanJian - Vue3 SPA 仪表板
 *
 * 使用 CDN Vue3 + Element Plus，纯静态无构建。
 */

const { createApp, ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } = Vue;

// ─────────────────────── App ───────────────────────

const app = createApp({
  setup() {
    // ── 路由状态 ──
    const currentPage = ref('dashboard');

    // ── 全局统计 ──
    const stats = reactive({
      total_findings: 0,
      false_positives: 0,
      likely_false_positives: 0,
      true_positives: 0,
      needs_review: 0,
      reduction_rate: '0%',
      total_scans: 0,
    });

    const statsCards = computed(() => [
      { label: '总扫描数', value: stats.total_scans, color: '#58a6ff' },
      { label: '总发现数', value: stats.total_findings, color: '#bc8cff' },
      { label: '误报数', value: stats.false_positives + stats.likely_false_positives, color: '#6e7681' },
      { label: '待复核', value: stats.needs_review, color: '#d29922' },
    ]);

    // ── 饼图数据 ──
    const pieData = computed(() => {
      const total = stats.total_findings || 1;
      const fp = stats.false_positives + stats.likely_false_positives;
      const tp = stats.true_positives;
      const review = stats.needs_review;
      return [
        { label: '误报', value: fp, color: '#6e7681', pct: (fp / total * 100).toFixed(1) },
        { label: '真实问题', value: tp, color: '#f85149', pct: (tp / total * 100).toFixed(1) },
        { label: '待复核', value: review, color: '#d29922', pct: (review / total * 100).toFixed(1) },
      ];
    });

    // ── 最近扫描 ──
    const recentScans = ref([]);

    // ── 扫描表单 ──
    const scanForm = reactive({
      projectPath: '',
      language: 'auto',
      scanners: ['semgrep'],
    });
    const scanning = ref(false);
    const scanProgress = reactive({
      show: false,
      percent: 0,
      message: '',
      status: '', // '' | 'running' | 'success' | 'exception'
      result: null,
    });

    const progressTagType = computed(() => {
      if (scanProgress.status === 'exception') return 'danger';
      if (scanProgress.status === 'success') return 'success';
      return 'warning';
    });
    const progressLabel = computed(() => {
      if (scanProgress.status === 'exception') return '失败';
      if (scanProgress.status === 'success') return '完成';
      return '运行中';
    });
    const progressStatus = computed(() => {
      if (scanProgress.status === 'exception') return 'exception';
      if (scanProgress.status === 'success') return 'success';
      return '';
    });

    // ── 发现列表 ──
    const findingsList = ref([]);
    const findingsLoading = ref(false);
    const findingsFilter = reactive({
      verdict: '',
      severity: '',
      search: '',
    });
    const currentScanId = ref('');

    // ── 详情页 ──
    const detailVisible = ref(false);
    const detailFinding = ref(null);
    const highlightedCode = ref('');

    // ── WebSocket ──
    let ws = null;
    const wsConnected = ref(false);

    // ═══════════════════ API 调用 ═══════════════════

    const API = '';

    async function apiFetch(path, options = {}) {
      try {
        const resp = await fetch(API + path, {
          headers: { 'Content-Type': 'application/json' },
          ...options,
        });
        if (!resp.ok) {
          const err = await resp.json().catch(() => ({ detail: resp.statusText }));
          throw new Error(err.detail || '请求失败');
        }
        return resp;
      } catch (e) {
        console.error(`API Error [${path}]:`, e);
        throw e;
      }
    }

    // ── 加载统计 ──
    async function loadStats() {
      try {
        const resp = await apiFetch('/api/v1/stats');
        const data = await resp.json();
        Object.assign(stats, data);
      } catch (e) {
        console.warn('加载统计失败:', e);
      }
    }

    // ── 加载最近扫描 ──
    async function loadRecentScans() {
      try {
        const resp = await apiFetch('/api/v1/scans');
        const data = await resp.json();
        recentScans.value = data.slice(0, 10);
      } catch (e) {
        console.warn('加载扫描列表失败:', e);
      }
    }

    // ── 启动扫描 ──
    async function startScan() {
      if (!scanForm.projectPath.trim()) {
        ElementPlus.ElMessage.warning('请输入项目路径');
        return;
      }
      scanning.value = true;
      scanProgress.show = true;
      scanProgress.percent = 10;
      scanProgress.message = '正在执行扫描...';
      scanProgress.status = 'running';
      scanProgress.result = null;

      try {
        const resp = await apiFetch('/api/v1/scan', {
          method: 'POST',
          body: JSON.stringify({
            project_path: scanForm.projectPath,
            language: scanForm.language,
            scanners: scanForm.scanners.length > 0 ? scanForm.scanners : null,
          }),
        });
        const data = await resp.json();
        currentScanId.value = data.scan_id;

        scanProgress.percent = 100;
        scanProgress.status = 'success';
        scanProgress.message = `扫描完成，共 ${data.total_findings} 个发现，耗时 ${data.duration_seconds}s`;
        scanProgress.result = data;

        // 连接 WebSocket
        connectWS(data.scan_id);

        // 刷新数据
        loadStats();
        loadRecentScans();

        ElementPlus.ElMessage.success('扫描完成');
      } catch (e) {
        scanProgress.status = 'exception';
        scanProgress.message = '扫描失败: ' + e.message;
        ElementPlus.ElMessage.error('扫描失败: ' + e.message);
      } finally {
        scanning.value = false;
      }
    }

    // ── 加载发现列表 ──
    let loadFindingsTimer = null;

    function debounceLoadFindings() {
      clearTimeout(loadFindingsTimer);
      loadFindingsTimer = setTimeout(loadFindings, 300);
    }

    async function loadFindings() {
      findingsLoading.value = true;
      try {
        const params = new URLSearchParams();
        if (currentScanId.value) params.append('scan_id', currentScanId.value);
        if (findingsFilter.verdict) params.append('verdict', findingsFilter.verdict);
        if (findingsFilter.severity) params.append('severity', findingsFilter.severity);
        if (findingsFilter.search) params.append('search', findingsFilter.search);

        const url = '/api/v1/findings' + (params.toString() ? '?' + params.toString() : '');
        const resp = await apiFetch(url);
        findingsList.value = await resp.json();
      } catch (e) {
        console.warn('加载发现列表失败:', e);
      } finally {
        findingsLoading.value = false;
      }
    }

    // ── 显示详情 ──
    async function showDetail(row) {
      try {
        const resp = await apiFetch('/api/v1/findings/' + row.id);
        detailFinding.value = await resp.json();
        detailVisible.value = true;

        // 代码高亮
        await nextTick();
        const code = detailFinding.value.original?.code || '';
        const lang = detailFinding.value.original?.metadata?.language || 'java';
        try {
          highlightedCode.value = Prism.highlight(
            code,
            Prism.languages[lang] || Prism.languages.java,
            lang
          );
        } catch {
          highlightedCode.value = escapeHtml(code);
        }
      } catch (e) {
        ElementPlus.ElMessage.error('加载详情失败');
      }
    }

    function closeDetail() {
      detailVisible.value = false;
    }

    // ── 标记误报 ──
    async function markFalsePositive(findingId) {
      try {
        const { value: reason } = await ElementPlus.ElMessageBox.prompt(
          '请输入误报原因',
          '标记为误报',
          { confirmButtonText: '确定', cancelButtonText: '取消', inputType: 'textarea' }
        );
        if (!reason) return;

        await apiFetch(`/api/v1/findings/${findingId}/mark-fp`, {
          method: 'POST',
          body: JSON.stringify({ reason, scope: 'instance' }),
        });
        ElementPlus.ElMessage.success('已标记为误报');
        loadStats();
        loadFindings();
        if (detailFinding.value?.id === findingId) {
          showDetail({ id: findingId });
        }
      } catch (e) {
        if (e !== 'cancel' && e?.message !== 'cancel') {
          ElementPlus.ElMessage.error('标记失败');
        }
      }
    }

    // ── 标记真实问题 ──
    async function markTruePositive(findingId) {
      try {
        await apiFetch(`/api/v1/findings/${findingId}/mark-tp`, {
          method: 'POST',
          body: JSON.stringify({ reason: '' }),
        });
        ElementPlus.ElMessage.success('已标记为真实问题');
        loadStats();
        loadFindings();
        if (detailFinding.value?.id === findingId) {
          showDetail({ id: findingId });
        }
      } catch (e) {
        ElementPlus.ElMessage.error('标记失败');
      }
    }

    // ── 导出报告 ──
    function exportCurrentFindings(format) {
      if (!currentScanId.value) {
        ElementPlus.ElMessage.warning('请先执行扫描');
        return;
      }
      window.open(`/api/v1/export/${currentScanId.value}?format=${format}`, '_blank');
    }

    function exportSingleFinding(format) {
      if (!detailFinding.value) return;
      // 生成单条发现的导出
      const f = detailFinding.value;
      const data = {
        id: f.id,
        rule_id: f.original.rule_id,
        severity: f.original.severity,
        file: f.original.file,
        line: f.original.line,
        verdict: f.verdict,
        confidence: f.confidence,
        risk_score: f.risk_score,
        recommendation: f.recommendation,
        filter_reasons: f.filter_reasons,
      };

      if (format === 'json') {
        downloadBlob(
          JSON.stringify(data, null, 2),
          `finding-${f.id?.slice(0, 8) || 'export'}.json`,
          'application/json'
        );
      } else {
        const md = [
          `# 发现详情`,
          ``,
          `- **规则ID**: ${data.rule_id}`,
          `- **严重程度**: ${data.severity}`,
          `- **文件**: \`${data.file}:${data.line}\``,
          `- **判定**: ${data.verdict}`,
          `- **置信度**: ${(data.confidence * 100).toFixed(1)}%`,
          `- **风险评分**: ${data.risk_score?.toFixed(1)} / 10`,
          `- **建议**: ${data.recommendation}`,
          ``,
          `## 过滤原因`,
          ``,
          ...(data.filter_reasons || []).map(r =>
            `- **[${r.filter_level}] ${r.rule_name}**: ${r.description} (${(r.confidence * 100).toFixed(0)}%)`
          ),
        ].join('\n');
        downloadBlob(md, `finding-${f.id?.slice(0, 8) || 'export'}.md`, 'text/markdown');
      }
    }

    function downloadBlob(content, filename, type) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }

    // ── WebSocket ──
    function connectWS(scanId) {
      if (ws) ws.close();

      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${location.host}/ws/scan/${scanId}`;

      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => { wsConnected.value = true; };
        ws.onclose = () => { wsConnected.value = false; };
        ws.onerror = () => { wsConnected.value = false; };
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            handleWSMessage(data);
          } catch (e) {
            console.warn('WS消息解析失败:', e);
          }
        };
      } catch (e) {
        console.warn('WebSocket连接失败:', e);
      }
    }

    function handleWSMessage(data) {
      switch (data.type) {
        case 'progress':
          scanProgress.percent = data.progress || scanProgress.percent;
          if (data.phase) scanProgress.message = `阶段: ${data.phase}`;
          break;
        case 'status':
          if (data.status === 'running') {
            scanProgress.message = '扫描进行中...';
          }
          break;
        case 'completed':
          scanProgress.percent = 100;
          scanProgress.status = 'success';
          scanProgress.message = '扫描完成';
          if (data.stats) {
            scanProgress.result = {
              ...scanProgress.result,
              statistics: data.stats,
            };
          }
          loadStats();
          loadFindings();
          break;
        case 'error':
          scanProgress.status = 'exception';
          scanProgress.message = '扫描出错: ' + (data.error || '未知错误');
          break;
      }
    }

    // ── 页面导航 ──
    function handleMenuSelect(index) {
      currentPage.value = index;
      if (index === 'dashboard') {
        loadStats();
        loadRecentScans();
        nextTick(drawPieChart);
      } else if (index === 'findings') {
        loadFindings();
      }
    }

    function goToFindings(scanId) {
      currentScanId.value = scanId || '';
      currentPage.value = 'findings';
      loadFindings();
    }

    // ── 饼图绘制（纯 Canvas） ──
    function drawPieChart() {
      const canvas = document.getElementById('pie-chart');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const dpr = window.devicePixelRatio || 1;
      const size = 300;
      canvas.width = size * dpr;
      canvas.height = size * dpr;
      canvas.style.width = size + 'px';
      canvas.style.height = size + 'px';
      ctx.scale(dpr, dpr);

      const cx = size / 2;
      const cy = size / 2;
      const radius = 110;
      const innerRadius = 60;

      ctx.clearRect(0, 0, size, size);

      const data = pieData.value;
      const total = data.reduce((s, d) => s + d.value, 0);
      if (total === 0) {
        ctx.fillStyle = '#30363d';
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.arc(cx, cy, innerRadius, 0, Math.PI * 2, true);
        ctx.fill();
        ctx.fillStyle = '#8b949e';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('暂无数据', cx, cy + 5);
        return;
      }

      let startAngle = -Math.PI / 2;
      data.forEach(item => {
        if (item.value === 0) return;
        const sliceAngle = (item.value / total) * Math.PI * 2;
        const endAngle = startAngle + sliceAngle;

        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, endAngle);
        ctx.arc(cx, cy, innerRadius, endAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = item.color;
        ctx.fill();

        // 标签
        const midAngle = startAngle + sliceAngle / 2;
        const labelR = radius + 20;
        const lx = cx + Math.cos(midAngle) * labelR;
        const ly = cy + Math.sin(midAngle) * labelR;
        ctx.fillStyle = '#8b949e';
        ctx.font = '12px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(`${item.pct}%`, lx, ly + 4);

        startAngle = endAngle;
      });

      // 中心文字
      ctx.fillStyle = '#e6edf3';
      ctx.font = 'bold 24px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(total, cx, cy + 2);
      ctx.fillStyle = '#8b949e';
      ctx.font = '12px sans-serif';
      ctx.fillText('总计', cx, cy + 18);
    }

    // ── 工具函数 ──
    function severityTagType(severity) {
      return {
        CRITICAL: 'danger',
        HIGH: '',
        MEDIUM: 'warning',
        LOW: 'success',
        INFO: 'info',
      }[severity] || 'info';
    }

    function verdictTagType(verdict) {
      return {
        false_positive: 'info',
        likely_false_positive: 'warning',
        true_positive: 'danger',
        needs_review: '',
      }[verdict] || '';
    }

    function verdictLabel(verdict) {
      return {
        false_positive: '误报',
        likely_false_positive: '疑似误报',
        true_positive: '真实问题',
        needs_review: '待复核',
      }[verdict] || verdict;
    }

    function formatTime(isoStr) {
      if (!isoStr) return '-';
      try {
        const d = new Date(isoStr);
        return d.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
      } catch {
        return isoStr;
      }
    }

    function escapeHtml(s) {
      if (!s) return '';
      return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ── 初始化 ──
    onMounted(async () => {
      await loadStats();
      await loadRecentScans();
      await nextTick();
      drawPieChart();
    });

    onUnmounted(() => {
      if (ws) ws.close();
    });

    // 饼图跟随数据变化重绘
    watch(pieData, () => {
      if (currentPage.value === 'dashboard') {
        nextTick(drawPieChart);
      }
    });

    return {
      // 路由
      currentPage,
      handleMenuSelect,
      goToFindings,

      // 统计
      stats,
      statsCards,
      pieData,

      // 最近扫描
      recentScans,

      // 扫描
      scanForm,
      scanning,
      scanProgress,
      progressTagType,
      progressLabel,
      progressStatus,
      startScan,

      // 发现列表
      findingsList,
      findingsLoading,
      findingsFilter,
      currentScanId,
      loadFindings,
      debounceLoadFindings,

      // 详情
      detailVisible,
      detailFinding,
      highlightedCode,
      showDetail,
      closeDetail,

      // 标记
      markFalsePositive,
      markTruePositive,

      // 导出
      exportCurrentFindings,
      exportSingleFinding,

      // WebSocket
      wsConnected,

      // 工具
      severityTagType,
      verdictTagType,
      verdictLabel,
      formatTime,
    };
  },
});

// 注册 Element Plus 图标
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component);
}

app.use(ElementPlus);
app.mount('#app');
