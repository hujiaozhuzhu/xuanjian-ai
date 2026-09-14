"""HTML 安全审计报告模板层。

本模块只承载 HTML / CSS / JS 模板字符串与纯渲染函数，不包含业务逻辑；
所有动态文本一律先经 :func:`esc`（``html.escape``）转义后再嵌入模板，
确保标题、描述、代码片段、截图说明等不可注入 HTML/JS。

页面能力：固定导航（severity 过滤 + 实时搜索 + 暗色切换）、侧边目录
（滚动高亮）、概览卡片、目标应用信息、findings 卡片（可展开详情、
时间线复现步骤、POC/EXP 危险折叠块、截图灯箱）、纯 CSS 条形统计、
附录，以及打印友好样式。零外部依赖，可离线双击打开。
"""

from __future__ import annotations

import html
from typing import Any, Dict, List

__all__ = [
    "SEVERITY_ORDER",
    "SEVERITY_LABELS",
    "CSS",
    "JS",
    "esc",
    "render_page",
    "render_nav",
    "render_sidebar",
    "render_header",
    "render_overview",
    "render_target",
    "render_summary",
    "render_finding_card",
    "render_stats",
    "render_appendix",
    "render_lightbox",
]

#: severity 固定展示顺序（高 -> 低）
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: severity 中文标签
SEVERITY_LABELS: Dict[str, str] = {
    "CRITICAL": "严重",
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "提示",
}

#: 目标应用字段中文标签
_TARGET_LABELS: Dict[str, str] = {
    "app_name": "应用名称",
    "package_name": "包名",
    "version_name": "版本名称",
    "version_code": "版本号",
    "min_sdk": "最低 SDK",
    "target_sdk": "目标 SDK",
    "file_size": "文件大小",
    "sha256": "SHA256",
}


def esc(text: Any) -> str:
    """HTML 转义（含引号），``None`` 视为空串。"""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


# ---------------------------------------------------------------------------
# 样式表：CSS 变量驱动亮 / 暗双主题，severity 配色遵循产品规范
# ---------------------------------------------------------------------------
CSS = """
:root{
--bg:#f1f5f9;--card:#ffffff;--text:#0f172a;--muted:#64748b;
--border:#e2e8f0;--accent:#2563eb;--code-bg:#f1f5f9;
--shadow:0 1px 3px rgba(15,23,42,.12);--radius:12px;--nav-h:56px;
--sev-critical:#7f1d1d;--sev-high:#dc2626;--sev-medium:#ea580c;
--sev-low:#ca8a04;--sev-info:#2563eb;
--soft-critical:#fee2e2;--soft-high:#fee2e2;--soft-medium:#ffedd5;
--soft-low:#fef9c3;--soft-info:#dbeafe;
}
html.dark{
--bg:#0b1220;--card:#151e2e;--text:#e2e8f0;--muted:#94a3b8;
--border:#2b3a55;--code-bg:#1c2739;--shadow:0 1px 4px rgba(0,0,0,.5);
--soft-critical:#451717;--soft-high:#3f1a1a;--soft-medium:#43270f;
--soft-low:#3a330b;--soft-info:#172a52;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",
"Hiragino Sans GB","Microsoft YaHei",sans-serif;font-size:14px;}
.navbar{position:fixed;top:0;left:0;right:0;height:var(--nav-h);z-index:50;
display:flex;align-items:center;gap:10px;padding:0 16px;
background:var(--card);border-bottom:1px solid var(--border);
box-shadow:var(--shadow);}
.nav-title{font-weight:700;font-size:15px;white-space:nowrap;
overflow:hidden;text-overflow:ellipsis;max-width:240px;}
.nav-btn{border:1px solid var(--border);background:transparent;
color:var(--muted);border-radius:8px;padding:5px 10px;font-size:12px;
cursor:pointer;white-space:nowrap;}
.nav-btn:hover{color:var(--text);border-color:var(--muted);}
#menu-toggle{display:none;}
.sev-filters{display:flex;gap:6px;flex-wrap:wrap;}
.sev-btn{border:1px solid var(--border);background:transparent;
color:var(--muted);border-radius:999px;padding:4px 10px;font-size:12px;
cursor:pointer;}
.sev-btn:hover{color:var(--text);}
.sev-btn.active{color:#fff;border-color:transparent;}
.sev-btn.active[data-sev="ALL"]{background:#334155;}
.sev-btn.active[data-sev="CRITICAL"]{background:var(--sev-critical);}
.sev-btn.active[data-sev="HIGH"]{background:var(--sev-high);}
.sev-btn.active[data-sev="MEDIUM"]{background:var(--sev-medium);}
.sev-btn.active[data-sev="LOW"]{background:var(--sev-low);}
.sev-btn.active[data-sev="INFO"]{background:var(--sev-info);}
.badge-count{display:inline-block;min-width:16px;padding:0 4px;
margin-left:4px;border-radius:999px;background:rgba(0,0,0,.18);
font-size:11px;text-align:center;}
#search-input{flex:1;min-width:110px;max-width:260px;height:30px;
padding:0 10px;border:1px solid var(--border);border-radius:8px;
background:var(--bg);color:var(--text);font-size:13px;}
.layout{display:flex;padding-top:var(--nav-h);}
.sidebar{width:240px;flex-shrink:0;position:sticky;top:var(--nav-h);
height:calc(100vh - var(--nav-h));overflow-y:auto;
border-right:1px solid var(--border);background:var(--card);
padding:12px 8px;}
.toc-title{font-size:12px;color:var(--muted);margin:4px 10px 8px;
letter-spacing:1px;}
.toc a{display:block;padding:6px 10px;border-radius:8px;
color:var(--muted);text-decoration:none;font-size:13px;line-height:1.4;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.toc a:hover{background:var(--bg);color:var(--text);}
.toc a.active{background:var(--soft-info);color:var(--accent);
font-weight:600;}
.toc-sev{display:inline-block;width:8px;height:8px;border-radius:50%;
margin-right:6px;vertical-align:middle;background:var(--muted);}
.toc-sev.sev-dot-critical{background:var(--sev-critical);}
.toc-sev.sev-dot-high{background:var(--sev-high);}
.toc-sev.sev-dot-medium{background:var(--sev-medium);}
.toc-sev.sev-dot-low{background:var(--sev-low);}
.toc-sev.sev-dot-info{background:var(--sev-info);}
.main{flex:1;min-width:0;max-width:1080px;margin:0 auto;
padding:20px 24px 64px;}
.report-header{margin:0 0 20px;}
.report-header h1{margin:0 0 6px;font-size:24px;line-height:1.3;}
.report-header .subtitle{margin:0 0 4px;color:var(--muted);font-size:14px;}
.report-header .header-meta{margin:0;color:var(--muted);font-size:12px;}
.section{background:var(--card);border:1px solid var(--border);
border-radius:var(--radius);box-shadow:var(--shadow);
padding:20px 22px;margin-bottom:20px;}
.section h2{margin:0 0 14px;font-size:16px;display:flex;
align-items:center;gap:8px;}
.section h2::before{content:"";width:4px;height:16px;border-radius:2px;
background:var(--accent);}
.overview{display:grid;grid-template-columns:repeat(auto-fit,
minmax(118px,1fr));gap:12px;margin-bottom:20px;}
.ov-card{background:var(--card);border:1px solid var(--border);
border-top:4px solid var(--muted);border-radius:var(--radius);
padding:14px 10px;text-align:center;box-shadow:var(--shadow);}
.ov-card.total{border-top-color:#334155;}
.ov-card.sev-critical{border-top-color:var(--sev-critical);}
.ov-card.sev-high{border-top-color:var(--sev-high);}
.ov-card.sev-medium{border-top-color:var(--sev-medium);}
.ov-card.sev-low{border-top-color:var(--sev-low);}
.ov-card.sev-info{border-top-color:var(--sev-info);}
.ov-num{font-size:26px;font-weight:700;}
.ov-label{font-size:12px;color:var(--muted);margin-top:2px;}
.finding-card{position:relative;background:var(--card);
border:1px solid var(--border);border-radius:var(--radius);
box-shadow:var(--shadow);margin-bottom:20px;overflow:hidden;}
.sev-bar{height:5px;}
.sev-critical .sev-bar{background:var(--sev-critical);}
.sev-high .sev-bar{background:var(--sev-high);}
.sev-medium .sev-bar{background:var(--sev-medium);}
.sev-low .sev-bar{background:var(--sev-low);}
.sev-info .sev-bar{background:var(--sev-info);}
.card-body{padding:16px 22px 20px;}
.card-head h3{margin:0 0 10px;font-size:17px;line-height:1.5;}
.vuln-id{color:var(--muted);font-weight:600;margin-right:8px;
font-family:ui-monospace,Consolas,monospace;font-size:14px;}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;}
.badge{font-size:11px;padding:2px 9px;border-radius:999px;
background:var(--bg);border:1px solid var(--border);color:var(--muted);}
.badge.sev-critical{background:var(--soft-critical);
color:var(--sev-critical);border-color:transparent;font-weight:600;}
.badge.sev-high{background:var(--soft-high);color:var(--sev-high);
border-color:transparent;font-weight:600;}
.badge.sev-medium{background:var(--soft-medium);color:var(--sev-medium);
border-color:transparent;font-weight:600;}
.badge.sev-low{background:var(--soft-low);color:var(--sev-low);
border-color:transparent;font-weight:600;}
.badge.sev-info{background:var(--soft-info);color:var(--sev-info);
border-color:transparent;font-weight:600;}
details.detail>summary{cursor:pointer;list-style:none;font-size:13px;
color:var(--accent);padding:6px 0;user-select:none;}
details.detail>summary::-webkit-details-marker{display:none;}
details.detail>summary::before{content:"\\25B8 ";}
details.detail[open]>summary::before{content:"\\25BE ";}
.detail-body{border-top:1px dashed var(--border);margin-top:6px;
padding-top:2px;}
.detail-body h4{font-size:12px;color:var(--muted);margin:18px 0 6px;
text-transform:uppercase;letter-spacing:1px;}
.detail-body p{margin:6px 0;line-height:1.7;}
p.desc{white-space:pre-line;}
p.muted-text{color:var(--muted);font-size:13px;}
pre.code{background:var(--code-bg);border:1px solid var(--border);
border-radius:8px;padding:10px 12px;margin:6px 0;
font-family:ui-monospace,SFMono-Regular,Consolas,"Courier New",
monospace;font-size:12.5px;line-height:1.55;overflow-x:auto;
white-space:pre-wrap;word-break:break-all;}
.evi-loc{font-size:12px;color:var(--muted);
font-family:ui-monospace,Consolas,monospace;margin:10px 0 2px;}
.evi-desc{font-size:12.5px;color:var(--muted);margin:4px 0;}
ol.timeline{list-style:none;margin:8px 0;padding:0 0 0 18px;
border-left:2px solid var(--border);}
ol.timeline li{margin:0 0 14px;padding-left:14px;position:relative;
line-height:1.6;}
ol.timeline li::before{content:"";position:absolute;left:-7px;top:5px;
width:10px;height:10px;border-radius:50%;background:var(--accent);}
.tl-res{font-size:12.5px;color:var(--muted);}
.tl-res .tl-expected::before{content:"期望: ";color:var(--sev-info);}
.tl-res .tl-actual::before{content:"实际: ";color:var(--sev-medium);}
.tl-res span{display:block;}
details.danger-block{margin:8px 0;}
details.danger-block>summary{cursor:pointer;list-style:none;
border-radius:8px;padding:8px 12px;font-size:13px;font-weight:600;
user-select:none;}
details.danger-block>summary::-webkit-details-marker{display:none;}
details.danger-block>summary::before{content:"\\25B8\\00A0";}
details.danger-block[open]>summary::before{content:"\\25BE\\00A0";}
details.danger-block.poc>summary{color:#fff;background:var(--sev-high);}
details.danger-block.exp>summary{color:#fff;background:var(--sev-medium);}
.fix-list{margin:6px 0;padding-left:20px;line-height:1.8;}
.ref-list{margin:6px 0;padding-left:20px;line-height:1.8;
word-break:break-all;}
.ref-list li{color:var(--accent);font-size:13px;}
.shot-grid{display:grid;grid-template-columns:repeat(auto-fill,
minmax(180px,1fr));gap:12px;}
.shot{margin:0;}
.shot img{width:100%;height:120px;object-fit:cover;
border:1px solid var(--border);border-radius:8px;cursor:zoom-in;
background:#fff;display:block;}
.shot figcaption{font-size:11px;color:var(--muted);margin-top:4px;
line-height:1.5;word-break:break-all;}
.shot-missing{height:120px;display:flex;align-items:center;
justify-content:center;border:1px dashed var(--border);
border-radius:8px;color:var(--muted);font-size:12px;
background:var(--bg);padding:10px;text-align:center;}
.over-badge{display:inline-block;background:var(--soft-medium);
color:var(--sev-medium);border-radius:999px;font-size:10px;
padding:1px 6px;margin-left:4px;white-space:nowrap;}
.kv-table{width:100%;border-collapse:collapse;font-size:13px;}
.kv-table th,.kv-table td{border:1px solid var(--border);
padding:8px 12px;text-align:left;vertical-align:top;}
.kv-table th{background:var(--bg);color:var(--muted);
font-weight:600;white-space:nowrap;width:150px;}
.bar-row{display:flex;align-items:center;gap:10px;margin:10px 0;}
.bar-label{width:140px;font-size:12px;color:var(--muted);
text-align:right;flex-shrink:0;}
.bar-track{flex:1;height:18px;background:var(--bg);
border-radius:999px;overflow:hidden;border:1px solid var(--border);}
.bar-fill{height:100%;border-radius:999px;min-width:2px;}
.bar-fill.sev-critical{background:var(--sev-critical);}
.bar-fill.sev-high{background:var(--sev-high);}
.bar-fill.sev-medium{background:var(--sev-medium);}
.bar-fill.sev-low{background:var(--sev-low);}
.bar-fill.sev-info{background:var(--sev-info);}
.bar-num{width:36px;font-size:13px;font-weight:600;}
.lightbox{position:fixed;inset:0;background:rgba(0,0,0,.86);
display:none;z-index:100;align-items:center;justify-content:center;
flex-direction:column;}
.lightbox.show{display:flex;}
.lightbox img{max-width:88vw;max-height:76vh;border-radius:8px;}
.lb-caption{color:#e2e8f0;margin-top:12px;font-size:14px;
max-width:80vw;text-align:center;word-break:break-all;}
.lb-sha{color:#94a3b8;font-size:12px;margin-top:4px;
font-family:ui-monospace,Consolas,monospace;}
.lb-close{position:absolute;top:14px;right:18px;background:transparent;
border:1px solid rgba(255,255,255,.4);color:#fff;border-radius:8px;
padding:5px 12px;cursor:pointer;font-size:13px;}
.lb-prev,.lb-next{position:absolute;top:50%;transform:translateY(-50%);
font-size:30px;line-height:1;background:transparent;border:none;
color:#fff;cursor:pointer;padding:14px;}
.lb-prev{left:10px;}.lb-next{right:10px;}
@media (max-width:900px){
.sidebar{position:fixed;left:0;top:var(--nav-h);z-index:60;width:230px;
transform:translateX(-105%);transition:transform .2s;
box-shadow:var(--shadow);}
.sidebar.open{transform:translateX(0);}
.nav-title{max-width:130px;}
#menu-toggle{display:inline-block;}
.sev-filters{display:none;}
}
@media print{
.navbar,.sidebar,.lightbox,.sev-filters,#search-input,.nav-btn{
display:none!important;}
.layout{padding-top:0;}
body{background:#fff;}
.main{max-width:none;padding:0;}
.finding-card,.section{box-shadow:none;break-inside:avoid;
page-break-inside:avoid;}
a{color:inherit;text-decoration:none;}
}
@page{margin:1.6cm;}
"""

# ---------------------------------------------------------------------------
# 页面脚本：主题切换 / 过滤搜索 / 滚动高亮 / 灯箱 / 打印展开
# ---------------------------------------------------------------------------
JS = """
(function () {
  'use strict';
  var root = document.documentElement;
  function applyTheme(t) { root.classList.toggle('dark', t === 'dark'); }
  try { applyTheme(localStorage.getItem('fp-theme') || 'light'); } catch (e) {}
  var themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var next = root.classList.contains('dark') ? 'light' : 'dark';
      applyTheme(next);
      try { localStorage.setItem('fp-theme', next); } catch (e) {}
    });
  }
  var menuBtn = document.getElementById('menu-toggle');
  var sidebar = document.getElementById('sidebar');
  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', function () {
      sidebar.classList.toggle('open');
    });
  }
  var cards = Array.prototype.slice.call(
    document.querySelectorAll('.finding-card'));
  var searchInput = document.getElementById('search-input');
  var activeSev = 'ALL';
  function applyFilter() {
    var q = searchInput ? searchInput.value.trim().toLowerCase() : '';
    cards.forEach(function (card) {
      var okSev = activeSev === 'ALL' ||
        card.getAttribute('data-sev') === activeSev;
      var hay = card.getAttribute('data-search') || '';
      var okQ = q === '' || hay.indexOf(q) !== -1;
      card.style.display = (okSev && okQ) ? '' : 'none';
    });
  }
  Array.prototype.forEach.call(
    document.querySelectorAll('.sev-btn'),
    function (btn) {
      btn.addEventListener('click', function () {
        activeSev = btn.getAttribute('data-sev') || 'ALL';
        Array.prototype.forEach.call(
          document.querySelectorAll('.sev-btn'),
          function (b) { b.classList.toggle('active', b === btn); });
        applyFilter();
      });
    });
  if (searchInput) {
    searchInput.addEventListener('input', applyFilter);
  }
  var links = Array.prototype.slice.call(
    document.querySelectorAll('.toc a'));
  function spy() {
    var pos = window.scrollY + 130;
    var current = null;
    cards.forEach(function (card) {
      if (card.offsetTop <= pos) { current = card.id; }
    });
    links.forEach(function (a) {
      a.classList.toggle('active',
        a.getAttribute('href') === '#' + current);
    });
  }
  window.addEventListener('scroll', spy, { passive: true });
  spy();
  function openByHash() {
    if (!location.hash) { return; }
    var card = document.querySelector(location.hash);
    if (card) {
      var d = card.querySelector('details.detail');
      if (d) { d.open = true; }
    }
  }
  window.addEventListener('hashchange', openByHash);
  var thumbs = Array.prototype.slice.call(
    document.querySelectorAll('.shot img.shot-thumb'));
  var lb = document.getElementById('lightbox');
  var lbImg = document.getElementById('lb-img');
  var lbCap = document.getElementById('lb-caption');
  var lbSha = document.getElementById('lb-sha');
  var idx = 0;
  function showShot(i) {
    if (!thumbs.length || !lb) { return; }
    idx = (i + thumbs.length) % thumbs.length;
    var im = thumbs[idx];
    lbImg.src = im.getAttribute('data-full') || im.src;
    lbCap.textContent = im.getAttribute('data-caption') || '';
    var sha = im.getAttribute('data-sha') || '';
    lbSha.textContent = sha ? 'SHA256: ' + sha : '';
    lb.classList.add('show');
  }
  function closeLb() { if (lb) { lb.classList.remove('show'); } }
  thumbs.forEach(function (im, i) {
    im.addEventListener('click', function () { showShot(i); });
  });
  if (lb) {
    document.getElementById('lb-close').addEventListener('click', closeLb);
    document.getElementById('lb-prev').addEventListener('click',
      function () { showShot(idx - 1); });
    document.getElementById('lb-next').addEventListener('click',
      function () { showShot(idx + 1); });
    lb.addEventListener('click', function (ev) {
      if (ev.target === lb) { closeLb(); }
    });
  }
  document.addEventListener('keydown', function (ev) {
    if (!lb || !lb.classList.contains('show')) { return; }
    if (ev.key === 'Escape') { closeLb(); }
    else if (ev.key === 'ArrowLeft') { showShot(idx - 1); }
    else if (ev.key === 'ArrowRight') { showShot(idx + 1); }
  });
  var openStates = [];
  window.addEventListener('beforeprint', function () {
    openStates = [];
    Array.prototype.forEach.call(document.querySelectorAll('details'),
      function (d) { openStates.push(d.open); d.open = true; });
  });
  window.addEventListener('afterprint', function () {
    var ds = document.querySelectorAll('details');
    Array.prototype.forEach.call(ds, function (d, i) {
      if (i < openStates.length) { d.open = openStates[i]; }
    });
  });
})();
"""

_HEAD_THEME_SCRIPT = (
    "<script>try{if(localStorage.getItem('fp-theme')==='dark')"
    "{document.documentElement.classList.add('dark');}}catch(e){}</script>"
)


def render_nav(title: str, counts: Dict[str, int], total: int) -> str:
    """渲染顶部固定导航栏：标题、severity 过滤按钮、搜索框、主题切换。"""
    buttons = [
        '<button class="sev-btn active" data-sev="ALL">全部'
        f'<span class="badge-count">{total}</span></button>'
    ]
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        buttons.append(
            f'<button class="sev-btn" data-sev="{sev}">'
            f'{SEVERITY_LABELS[sev]}'
            f'<span class="badge-count">{n}</span></button>'
        )
    return (
        '<nav class="navbar">'
        '<button id="menu-toggle" class="nav-btn" '
        'aria-label="打开目录">目录</button>'
        f'<div class="nav-title">{esc(title)}</div>'
        f'<div class="sev-filters">{"".join(buttons)}</div>'
        '<input id="search-input" type="search" '
        'placeholder="搜索标题 / 描述 / CWE" aria-label="搜索漏洞">'
        '<button id="theme-toggle" class="nav-btn" '
        'aria-label="切换暗色模式">暗色</button>'
        '</nav>'
    )


def render_sidebar(items: List[Dict[str, str]]) -> str:
    """渲染侧边目录（锚点跳转，滚动时由脚本高亮当前项）。"""
    links = "".join(
        f'<a href="#{esc(it["anchor"])}">'
        f'<span class="toc-sev sev-dot-{esc(str(it["sev"]).lower())}">'
        f'</span>{esc(it["label"])}</a>'
        for it in items
    )
    return (
        '<aside id="sidebar" class="sidebar">'
        '<div class="toc-title">漏洞目录</div>'
        f'<nav class="toc">{links}</nav></aside>'
    )


def render_header(meta: Dict[str, Any]) -> str:
    """渲染报告主标题区（标题 / 副标题 / 公司与版本等元信息）。"""
    parts = [
        '<header class="report-header">',
        f'<h1>{esc(meta.get("title", ""))}</h1>',
    ]
    sub = str(meta.get("subtitle", "") or "")
    if sub:
        parts.append(f'<p class="subtitle">{esc(sub)}</p>')
    bits: List[str] = []
    if meta.get("company"):
        bits.append(esc(meta["company"]))
    if meta.get("classification"):
        bits.append(esc(meta["classification"]))
    if meta.get("report_version"):
        bits.append("报告版本 " + esc(meta["report_version"]))
    if meta.get("scan_date"):
        bits.append("扫描日期 " + esc(meta["scan_date"]))
    if bits:
        parts.append(f'<p class="header-meta">{" · ".join(bits)}</p>')
    parts.append("</header>")
    return "".join(parts)


def render_overview(total: int, counts: Dict[str, int]) -> str:
    """渲染概览卡片行：总数 + 各 severity 计数色块卡片。"""
    cards = [
        '<div class="ov-card total">'
        f'<div class="ov-num">{total}</div>'
        '<div class="ov-label">漏洞总数</div></div>'
    ]
    for sev in SEVERITY_ORDER:
        cards.append(
            f'<div class="ov-card sev-{sev.lower()}">'
            f'<div class="ov-num">{counts.get(sev, 0)}</div>'
            f'<div class="ov-label">{SEVERITY_LABELS[sev]} {sev}</div></div>'
        )
    return f'<section class="overview">{"".join(cards)}</section>'


def render_target(target: Dict[str, str]) -> str:
    """渲染目标 APP 信息卡；无信息时返回空串。"""
    if not target:
        return ""
    rows = "".join(
        f"<tr><th>{esc(_TARGET_LABELS.get(k, k))}</th>"
        f"<td>{esc(v)}</td></tr>"
        for k, v in target.items()
    )
    return (
        '<section class="section" id="target-section">'
        '<h2>目标应用信息</h2>'
        f'<table class="kv-table">{rows}</table></section>'
    )


def render_summary(text: str) -> str:
    """渲染评估摘要区块；文本为空时返回空串。"""
    if not str(text or "").strip():
        return ""
    return (
        '<section class="section" id="summary-section">'
        '<h2>评估摘要</h2>'
        f'<p class="desc">{esc(text)}</p></section>'
    )


def _render_screenshot(shot: Dict[str, Any]) -> str:
    """渲染单张截图：成功为缩略图 figure，失败为占位框 + 原因。"""
    caption = esc(shot.get("caption", ""))
    if shot.get("state") == "ok":
        over = ""
        if shot.get("oversize"):
            over = (
                '<span class="over-badge">超大图片 '
                f'{esc(shot.get("size_mb", 0.0))} MB</span>'
            )
        uri = shot.get("data_uri", "")
        sha = esc(shot.get("sha16", ""))
        return (
            '<figure class="shot">'
            f'<img class="shot-thumb" src="{uri}" '
            f'data-full="{uri}" data-caption="{caption}" '
            f'data-sha="{sha}" alt="漏洞截图">'
            f'<figcaption>{caption}{over}</figcaption></figure>'
        )
    reason = esc(shot.get("reason", "未知原因"))
    return (
        '<figure class="shot">'
        f'<div class="shot-missing">截图缺失：{reason}</div>'
        f'<figcaption>{caption}</figcaption></figure>'
    )


def _render_evidence_block(evi: Dict[str, str]) -> str:
    """渲染单条证据：代码位置 + 等宽浅灰底代码块 + 可选说明。"""
    parts = ['<div class="evi">']
    loc = str(evi.get("location", "") or "")
    if loc:
        parts.append(f'<div class="evi-loc">{esc(loc)}</div>')
    content = str(evi.get("content", "") or "")
    if content:
        parts.append(f'<pre class="code">{esc(content)}</pre>')
    desc = str(evi.get("description", "") or "")
    if desc:
        parts.append(f'<div class="evi-desc">{esc(desc)}</div>')
    parts.append("</div>")
    return "".join(parts)


def _render_step_item(step: Dict[str, str]) -> str:
    """渲染时间线中的单个复现步骤。"""
    parts = [f'<div class="tl-action">{esc(step.get("action", ""))}</div>']
    cmd = str(step.get("command", "") or "")
    if cmd:
        parts.append(f'<pre class="code">{esc(cmd)}</pre>')
    expected = str(step.get("expected", "") or "")
    actual = str(step.get("actual", "") or "")
    if expected or actual:
        parts.append(
            '<div class="tl-res">'
            f'<span class="tl-expected">{esc(expected)}</span>'
            f'<span class="tl-actual">{esc(actual)}</span></div>'
        )
    return f"<li>{''.join(parts)}</li>"


def render_finding_card(f: Dict[str, Any]) -> str:
    """渲染单个 finding 卡片（标题区 + 可展开详情 + 截图网格）。"""
    sev = str(f.get("severity", "INFO"))
    badges = [
        f'<span class="badge sev-{sev.lower()}">'
        f'{SEVERITY_LABELS.get(sev, sev)}</span>'
    ]
    if f.get("category"):
        badges.append(f'<span class="badge">{esc(f["category"])}</span>')
    if f.get("cwe"):
        badges.append(f'<span class="badge">{esc(f["cwe"])}</span>')
    if f.get("masvs"):
        badges.append(f'<span class="badge">{esc(f["masvs"])}</span>')
    if f.get("confidence"):
        badges.append(
            f'<span class="badge">置信度: {esc(f["confidence"])}</span>'
        )

    body: List[str] = []
    if f.get("description"):
        body.append("<h4>漏洞描述</h4>")
        body.append(f'<p class="desc">{esc(f["description"])}</p>')
    if f.get("impact"):
        body.append("<h4>危害影响</h4>")
        body.append(f'<p class="desc">{esc(f["impact"])}</p>')
    components = list(f.get("components", []) or [])
    if components:
        body.append("<h4>受影响组件</h4>")
        body.append(
            '<p class="muted-text">'
            f'{esc(", ".join(str(c) for c in components))}</p>'
        )
    evidence = list(f.get("evidence", []) or [])
    if evidence:
        body.append("<h4>证据</h4>")
        body.extend(_render_evidence_block(e) for e in evidence)
    steps = list(f.get("steps", []) or [])
    if steps:
        body.append("<h4>复现步骤</h4>")
        body.append(
            '<ol class="timeline">'
            + "".join(_render_step_item(s) for s in steps)
            + "</ol>"
        )
    poc = str(f.get("poc", "") or "")
    if poc.strip():
        body.append(
            '<details class="danger-block poc">'
            '<summary>危险代码（POC）— 仅限授权测试环境使用，'
            "点击展开</summary>"
            f'<pre class="code">{esc(poc)}</pre></details>'
        )
    exp = str(f.get("exp", "") or "")
    if exp.strip():
        body.append(
            '<details class="danger-block exp">'
            "<summary>利用信息（EXP）— 受控利用说明，点击展开</summary>"
            f'<pre class="code">{esc(exp)}</pre></details>'
        )
    fixes = list(f.get("fixes", []) or [])
    if fixes:
        body.append("<h4>修复建议</h4>")
        body.append(
            '<ul class="fix-list">'
            + "".join(f"<li>{esc(x)}</li>" for x in fixes)
            + "</ul>"
        )
    shots = list(f.get("screenshots", []) or [])
    if shots:
        body.append("<h4>截图证据</h4>")
        body.append(
            '<div class="shot-grid">'
            + "".join(_render_screenshot(s) for s in shots)
            + "</div>"
        )
    refs = list(f.get("references", []) or [])
    if refs:
        body.append("<h4>参考链接</h4>")
        body.append(
            '<ul class="ref-list">'
            + "".join(f"<li>{esc(r)}</li>" for r in refs)
            + "</ul>"
        )
    if not body:
        body.append('<p class="muted-text">暂无详细信息。</p>')

    return (
        f'<article class="finding-card sev-{sev.lower()}" '
        f'id="{esc(f.get("anchor", ""))}" data-sev="{sev}" '
        f'data-search="{esc(f.get("search_blob", ""))}">'
        '<div class="sev-bar"></div>'
        '<div class="card-body">'
        '<div class="card-head">'
        f'<h3><span class="vuln-id">{esc(f.get("vuln_id", ""))}</span>'
        f'{esc(f.get("title", ""))}</h3></div>'
        f'<div class="badges">{"".join(badges)}</div>'
        '<details class="detail"><summary>展开详情</summary>'
        f'<div class="detail-body">{"".join(body)}</div>'
        "</details></div></article>"
    )


def render_stats(counts: Dict[str, int], total: int) -> str:
    """渲染 severity 分布纯 CSS 条形图。"""
    rows: List[str] = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        pct = round(n / total * 100, 1) if total else 0.0
        rows.append(
            '<div class="bar-row">'
            f'<span class="bar-label">{SEVERITY_LABELS[sev]} {sev}</span>'
            '<div class="bar-track">'
            f'<div class="bar-fill sev-{sev.lower()}" '
            f'style="width:{pct}%"></div></div>'
            f'<span class="bar-num">{n}</span></div>'
        )
    return (
        '<section class="section" id="stats-section">'
        "<h2>严重度分布</h2>"
        f'{"".join(rows)}</section>'
    )


def render_appendix(meta: Dict[str, Any]) -> str:
    """渲染附录：环境信息与复现说明。"""
    parts = ['<section class="section" id="appendix-section">',
             "<h2>附录</h2>"]
    env = list(meta.get("env", []) or [])
    if env:
        rows = "".join(
            f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in env
        )
        parts.append("<h4>测试环境信息</h4>")
        parts.append(f'<table class="kv-table">{rows}</table>')
    for key, label in (("test_scope", "测试范围"),
                       ("test_methods", "测试方法")):
        items = [str(x) for x in (meta.get(key, []) or []) if str(x).strip()]
        if items:
            parts.append(f"<h4>{esc(label)}</h4>")
            parts.append(
                '<ul class="fix-list">'
                + "".join(f"<li>{esc(x)}</li>" for x in items)
                + "</ul>"
            )
    parts.append("<h4>复现说明</h4>")
    parts.append(
        '<p class="muted-text">本报告所含 POC / EXP 仅用于授权范围内的'
        "安全评估与修复验证，请在隔离测试环境中复现，严禁用于未授权"
        "目标。复现前请确认已获得目标系统所有者的书面授权。</p>"
    )
    cmds = [str(x) for x in (meta.get("cli_commands", []) or [])
            if str(x).strip()]
    if cmds:
        parts.append("<h4>相关扫描命令</h4>")
        parts.append(
            f'<pre class="code">{esc(chr(10).join(cmds))}</pre>'
        )
    parts.append("</section>")
    return "".join(parts)


def render_lightbox() -> str:
    """渲染截图灯箱（大图查看 / 左右切换 / ESC 关闭）。"""
    return (
        '<div id="lightbox" class="lightbox" role="dialog" '
        'aria-modal="true" aria-label="截图大图查看">'
        '<button id="lb-close" class="lb-close" '
        'aria-label="关闭">关闭</button>'
        '<button id="lb-prev" class="lb-prev" '
        'aria-label="上一张">&#8249;</button>'
        '<img id="lb-img" alt="截图大图">'
        '<button id="lb-next" class="lb-next" '
        'aria-label="下一张">&#8250;</button>'
        '<div id="lb-caption" class="lb-caption"></div>'
        '<div id="lb-sha" class="lb-sha"></div></div>'
    )


def render_page(ctx: Dict[str, str]) -> str:
    """组装完整 HTML 文档（所有 CSS / JS 内联，单文件自包含）。"""
    parts = [
        "<!DOCTYPE html>\n",
        '<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n',
        '<meta name="viewport" content="width=device-width, '
        'initial-scale=1">\n',
        f"<title>{esc(ctx.get('title', ''))}</title>\n",
        _HEAD_THEME_SCRIPT,
        "\n<style>\n",
        CSS,
        "\n</style>\n</head>\n<body>\n",
        ctx.get("nav", ""),
        '\n<div class="layout">\n',
        ctx.get("sidebar", ""),
        '\n<main class="main">\n',
        ctx.get("header", ""),
        ctx.get("overview", ""),
        ctx.get("target", ""),
        ctx.get("summary", ""),
        ctx.get("findings", ""),
        ctx.get("stats", ""),
        ctx.get("appendix", ""),
        "\n</main>\n</div>\n",
        ctx.get("lightbox", ""),
        "\n<script>\n",
        JS,
        "\n</script>\n</body>\n</html>",
    ]
    return "".join(parts)
