/**
 * XuanJian v3.1 - UI Engine
 * DOM helpers, notifications, modal dialogs
 * All text insertion uses XSS.escapeHtml for safety
 */
(function (global) {
  'use strict';

  function $(sel, parent) {
    return (parent || document).querySelector(sel);
  }

  function $$(sel, parent) {
    return Array.prototype.slice.call((parent || document).querySelectorAll(sel));
  }

  /**
   * Clear and render content into main container
   */
  function render(html) {
    var main = document.getElementById('xj-main');
    if (main) {
      main.innerHTML = '';
      if (typeof html === 'string') {
        main.innerHTML = html;
      } else if (html instanceof Node) {
        main.appendChild(html);
      }
    }
  }

  /**
   * Toast notification
   */
  function toast(message, type, duration) {
    type = type || 'info';
    duration = duration || 3000;
    var container = document.getElementById('xj-toast-container');
    if (!container) return;

    var icons = { success: '✓', error: '✕', info: 'ℹ' };
    var el = document.createElement('div');
    el.className = 'xj-toast ' + type;
    el.innerHTML = '<span>' + (icons[type] || '') + '</span><span>' + XSS.escapeHtml(message) + '</span>';
    container.appendChild(el);

    setTimeout(function() {
      el.style.opacity = '0';
      el.style.transform = 'translateX(20px)';
      el.style.transition = 'all 0.3s ease';
      setTimeout(function() { el.remove(); }, 300);
    }, duration);
  }

  /**
   * Confirm dialog
   */
  function confirm(message, title) {
    title = title || '确认操作';
    return new Promise(function(resolve) {
      var overlay = document.getElementById('xj-modal-overlay');
      if (!overlay) { resolve(false); return; }

      overlay.innerHTML =
        '<div class="xj-modal">' +
          '<div class="xj-modal-header"><span class="xj-modal-title">' + XSS.escapeHtml(title) + '</span><button class="xj-modal-close" id="xj-confirm-close">&times;</button></div>' +
          '<div class="xj-modal-body"><p>' + XSS.escapeHtml(message) + '</p></div>' +
          '<div class="xj-modal-footer">' +
            '<button class="xj-btn" id="xj-confirm-cancel">取消</button>' +
            '<button class="xj-btn xj-btn-primary" id="xj-confirm-ok">确定</button>' +
          '</div>' +
        '</div>';
      overlay.removeAttribute('hidden');

      function close(result) {
        overlay.setAttribute('hidden', '');
        overlay.innerHTML = '';
        resolve(result);
      }

      document.getElementById('xj-confirm-ok').onclick = function() { close(true); };
      document.getElementById('xj-confirm-cancel').onclick = function() { close(false); };
      document.getElementById('xj-confirm-close').onclick = function() { close(false); };
    });
  }

  /**
   * Input dialog (prompt)
   */
  function prompt(message, defaultValue) {
    defaultValue = defaultValue || '';
    return new Promise(function(resolve) {
      var overlay = document.getElementById('xj-modal-overlay');
      if (!overlay) { resolve(null); return; }

      overlay.innerHTML =
        '<div class="xj-modal">' +
          '<div class="xj-modal-header"><span class="xj-modal-title">' + XSS.escapeHtml(message) + '</span><button class="xj-modal-close" id="xj-prompt-close">&times;</button></div>' +
          '<div class="xj-modal-body"><textarea class="xj-textarea" id="xj-prompt-input"></textarea></div>' +
          '<div class="xj-modal-footer">' +
            '<button class="xj-btn" id="xj-prompt-cancel">取消</button>' +
            '<button class="xj-btn xj-btn-primary" id="xj-prompt-ok">确定</button>' +
          '</div>' +
        '</div>';
      overlay.removeAttribute('hidden');

      var input = document.getElementById('xj-prompt-input');
      input.value = defaultValue;
      input.focus();

      function close(result) {
        overlay.setAttribute('hidden', '');
        overlay.innerHTML = '';
        resolve(result);
      }

      document.getElementById('xj-prompt-ok').onclick = function() { close(input.value); };
      document.getElementById('xj-prompt-cancel').onclick = function() { close(null); };
      document.getElementById('xj-prompt-close').onclick = function() { close(null); };
    });
  }

  /**
   * Open a custom modal
   */
  function modal(content, options) {
    options = options || {};
    var overlay = document.getElementById('xj-modal-overlay');
    if (!overlay) return;

    var bodyHtml = typeof content === 'string' ? content : '';
    overlay.innerHTML =
      '<div class="xj-modal' + (options.wide ? ' xj-modal-wide' : '') + '">' +
        '<div class="xj-modal-header">' +
          '<span class="xj-modal-title">' + XSS.escapeHtml(options.title || '') + '</span>' +
          '<button class="xj-modal-close" id="xj-modal-close-btn">&times;</button>' +
        '</div>' +
        '<div class="xj-modal-body">' + bodyHtml + '</div>' +
        (options.footer ? '<div class="xj-modal-footer">' + options.footer + '</div>' : '') +
      '</div>';
    overlay.removeAttribute('hidden');

    var closeBtn = document.getElementById('xj-modal-close-btn');
    if (closeBtn) {
      closeBtn.onclick = function() { UI.closeModal(); if (options.onClose) options.onClose(); };
    }
  }

  /**
   * Close modal
   */
  function closeModal() {
    var overlay = document.getElementById('xj-modal-overlay');
    if (overlay) {
      overlay.setAttribute('hidden', '');
      overlay.innerHTML = '';
    }
  }

  /**
   * Format timestamp to readable string
   */
  function formatTime(isoStr) {
    if (!isoStr) return '-';
    try {
      var d = new Date(isoStr);
      return d.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    } catch (e) { return isoStr; }
  }

  /**
   * Format relative time
   */
  function timeAgo(isoStr) {
    if (!isoStr) return '-';
    try {
      var diff = (Date.now() - new Date(isoStr).getTime()) / 1000;
      if (diff < 60) return Math.floor(diff) + '秒前';
      if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
      if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
      return Math.floor(diff / 86400) + '天前';
    } catch (e) { return isoStr; }
  }

  /**
   * Get severity color
   */
  function severityColor(sev) {
    var map = { CRITICAL: '#f85149', HIGH: '#d29922', MEDIUM: '#e3b341', LOW: '#3fb950', INFO: '#58a6ff' };
    return map[sev] || '#6e7681';
  }

  /**
   * Get verdict label
   */
  function verdictLabel(v) {
    var map = { false_positive: '误报', likely_false_positive: '疑似误报', true_positive: '真实问题', needs_review: '待复核' };
    return map[v] || v || '未知';
  }

  var UI = {
    $: $,
    $$: $$,
    render: render,
    toast: toast,
    confirm: confirm,
    prompt: prompt,
    modal: modal,
    closeModal: closeModal,
    formatTime: formatTime,
    timeAgo: timeAgo,
    severityColor: severityColor,
    verdictLabel: verdictLabel
  };

  global.UI = UI;
})(window);
