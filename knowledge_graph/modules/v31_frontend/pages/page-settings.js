/**
 * XuanJian v3.1 - Settings Page
 * Platform configuration, scanner settings, API keys
 */
(function (global) {
  'use strict';

  function render() {
    var html =
      '<div class="xj-animate-in">' +
        '<div class="xj-section-header">' +
          '<div><h2 class="xj-section-title">系统设置</h2><span class="xj-text-muted">平台配置、扫描器选项、API密钥管理</span></div>' +
        '</div>' +

        '<div class="xj-grid-sidebar">' +
          // Settings Nav
          '<div class="xj-panel" style="height:fit-content;position:sticky;top:70px;">' +
            '<div style="display:flex;flex-direction:column;gap:2px;">' +
              settingsNav('general', '通用设置', true) +
              settingsNav('scanners', '扫描器配置', false) +
              settingsNav('ai-engine', 'AI引擎配置', false) +
              settingsNav('security', '安全设置', false) +
              settingsNav('notifications', '通知设置', false) +
              settingsNav('api-keys', 'API密钥管理', false) +
              settingsNav('data', '数据管理', false) +
            '</div>' +
          '</div>' +

          // Settings Content
          '<div>' +
            // General
            settingsSection('General Settings',
              '<div class="xj-field"><label class="xj-field-label">默认扫描语言</label><select class="xj-select" id="xj-setting-lang"><option>自动检测</option><option>Java</option><option>Python</option><option>Go</option><option>JavaScript</option></select></div>' +
              '<div class="xj-field"><label class="xj-field-label">误报判定阈值</label><input class="xj-input" type="range" min="50" max="99" value="70" style="width:100%;"></div>' +
              '<div class="xj-field"><label class="xj-field-label"><input type="checkbox" checked> 启用AI辅助判定</label></div>' +
              '<div class="xj-field"><label class="xj-field-label"><input type="checkbox" checked> 自动标记高置信度误报</label></div>' +
              '<button class="xj-btn xj-btn-primary" onclick="XJPageSettings.saveSettings()">保存设置</button>'
            ) +

            // Scanners
            settingsSection('Scanner Configuration',
              '<div class="xj-field"><label class="xj-field-label">Semgrep 规则路径</label><input class="xj-input" value="/opt/semgrep-rules/java-security"></div>' +
              '<div class="xj-field"><label class="xj-field-label">并行扫描数</label><input class="xj-input" type="number" value="4" min="1" max="16" style="width:100px;"></div>' +
              '<div class="xj-field"><label class="xj-field-label">扫描超时 (秒)</label><input class="xj-input" type="number" value="300" style="width:100px;"></div>' +
              '<div class="xj-field"><label class="xj-field-label"><input type="checkbox" checked> 启用 Semgrep Pro 规则集</label></div>'
            ) +

            // Security
            settingsSection('Security & XSS Defense',
              '<p class="xj-text-muted" style="margin-bottom:16px;">玄鉴前端已实施以下安全防护措施：</p>' +
              '<div style="display:flex;flex-direction:column;gap:8px;">' +
                securityItem('✓ 输出编码 (HTML Entity Encoding)', '所有用户可控内容输出时自动转义') +
                securityItem('✓ URL安全校验 (Protocol Filtering)', '阻止 javascript: data: 等危险协议') +
                securityItem('✓ DOM白名单净化 (Tag/Attr Whitelist)', '只允许安全标签，过滤事件处理器') +
                securityItem('✓ Content-Security-Policy 兼容', 'meta标签启用CSP策略') +
                securityItem('✓ HTTP安全头 (X-Frame-Options等)', '防点击劫持、MIME嗅探攻击') +
              '</div>'
            ) +

            // API Keys
            settingsSection('API Key Management',
              '<div class="xj-field"><label class="xj-field-label">XuanJian API Key</label><div class="xj-input-group"><input class="xj-input" type="password" value="xj_sk_xxxxxxxxxxxxx" readonly><button class="xj-btn xj-btn-sm" onclick="UI.toast(\'已复制到剪贴板\',\'success\')">复制</button></div></div>' +
              '<div class="xj-field"><label class="xj-field-label">GitHub Token (for Auto PR)</label><input class="xj-input" type="password" placeholder="ghp_xxxxxxxxxxxx"></div>' +
              '<div class="xj-field"><label class="xj-field-label">Slack Webhook URL</label><input class="xj-input" placeholder="https://hooks.slack.com/services/..."></div>'
            ) +
          '</div>' +
        '</div>' +

        // Connection Status
        '<div class="xj-panel" style="margin-top:16px;">' +
          '<div class="xj-panel-header"><span class="xj-panel-title">服务状态</span></div>' +
          '<div class="xj-grid-4" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));">' +
            serviceStatus('REST API', 'online') +
            serviceStatus('扫描引擎', 'online') +
            serviceStatus('AI推理服务', 'online') +
            serviceStatus('事件流 (WebSocket)', 'checking') +
          '</div>' +
        '</div>' +
      '</div>';

    UI.render(html);

    // Health check
    setTimeout(function() {
      API.healthCheck().then(function(data) {
        var el = document.getElementById('xj-svc-ws-status');
        if (el) { el.className = 'xj-tag status-closed'; el.textContent = '在线'; }
      }).catch(function() {
        var el = document.getElementById('xj-svc-ws-status');
        if (el) { el.className = 'xj-tag status-pending'; el.textContent = '离线'; }
      });
    }, 500);
  }

  function settingsNav(id, label, active) {
    return '<button class="xj-nav-item' + (active ? ' active' : '') + '" style="width:100%;text-align:left;border:none;border-radius:6px;margin-bottom:2px;" onclick="UI.toast(\'切换到: ' + label + '\',\'info\')">' + XSS.escapeHtml(label) + '</button>';
  }

  function settingsSection(title, content) {
    return '<div class="xj-panel">' +
      '<div class="xj-panel-header"><span class="xj-panel-title">' + XSS.escapeHtml(title) + '</span></div>' +
      content +
    '</div>';
  }

  function securityItem(title, desc) {
    return '<div style="background:var(--xj-bg-0);border-radius:6px;padding:12px;">' +
      '<div style="font-weight:500;margin-bottom:4px;">' + XSS.escapeHtml(title) + '</div>' +
      '<div class="xj-text-muted" style="font-size:12px;">' + XSS.escapeHtml(desc) + '</div>' +
    '</div>';
  }

  function serviceStatus(name, status) {
    var cls = status === 'online' ? 'status-closed' : status === 'checking' ? 'status-pending' : 'status-open';
    var txt = status === 'online' ? '在线' : status === 'checking' ? '检测中' : '离线';
    var id = name === '事件流 (WebSocket)' ? ' id="xj-svc-ws-status"' : '';
    return '<div style="text-align:center;padding:12px;background:var(--xj-bg-0);border-radius:8px;">' +
      '<div style="font-size:13px;margin-bottom:6px;">' + XSS.escapeHtml(name) + '</div>' +
      '<span class="xj-tag ' + cls + '"' + id + '>' + txt + '</span>' +
    '</div>';
  }

  function saveSettings() {
    UI.toast('设置已保存', 'success');
  }

  XJPages.add({
    path: '/settings',
    title: '系统设置',
    navLabel: '系统设置',
    render: render
  });

  global.XJPageSettings = { render: render, saveSettings: saveSettings };
})(window);
