/**
 * XuanJian v3.1 - XSS Defense Layer
 * All user input/output must go through this module
 * Strategy: Input filtering + Output encoding + CSP-compatible + DOM sanitization
 */
(function (global) {
  'use strict';

  var XSS = {
    /**
     * HTML entity encoding - safe for textContent/attribute values
     */
    escapeHtml: function(str) {
      if (str == null) return '';
      var div = document.createElement('div');
      div.textContent = String(str);
      return div.innerHTML;
    },

    /**
     * Attribute value encoding - for href/src/on* attributes
     */
    escapeAttr: function(str) {
      if (str == null) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\//g, '&#x2F;');
    },

    /**
     * URL safety check - block javascript: data: and other dangerous protocols
     */
    sanitizeUrl: function(url) {
      if (!url) return '#';
      var trimmed = String(url).trim().toLowerCase();
      if (trimmed.indexOf('javascript:') === 0 || trimmed.indexOf('data:') === 0 || trimmed.indexOf('vbscript:') === 0) {
        return '#blocked';
      }
      return String(url);
    },

    /**
     * Strip all HTML tags - pure text extraction
     */
    stripTags: function(str) {
      if (str == null) return '';
      return String(str).replace(/<[^>]*>/g, '');
    },

    /**
     * HTML sanitization - only allow whitelisted tags and attributes
     */
    sanitizeHtml: function(html) {
      if (!html) return '';
      var parser = new DOMParser();
      var doc = parser.parseFromString(String(html), 'text/html');
      var allowedTags = ['b','i','em','strong','code','pre','br','p','ul','ol','li','span','div'];
      var allowedAttrs = ['class'];

      function isAllowedTag(tag) {
        return allowedTags.indexOf(tag.toLowerCase()) !== -1;
      }

      function cleanNode(node) {
        var children = Array.prototype.slice.call(node.childNodes);
        for (var i = 0; i < children.length; i++) {
          var child = children[i];
          if (child.nodeType === 1) {
            var tag = child.tagName.toLowerCase();
            if (!isAllowedTag(tag)) {
              var frag = document.createDocumentFragment();
              while (child.firstChild) frag.appendChild(child.firstChild);
              node.replaceChild(frag, child);
            } else {
              var attrs = Array.prototype.slice.call(child.attributes);
              for (var j = 0; j < attrs.length; j++) {
                if (allowedAttrs.indexOf(attrs[j].name.toLowerCase()) === -1) {
                  child.removeAttribute(attrs[j].name);
                }
              }
              cleanNode(child);
            }
          }
        }
      }

      cleanNode(doc.body);
      return doc.body.innerHTML;
    },

    /**
     * Create safe DOM element
     */
    safeCreate: function(tag, attrs, textContent) {
      attrs = attrs || {};
      var el = document.createElement(tag);
      Object.keys(attrs).forEach(function(k) {
        var v = attrs[k];
        if (k === 'class') el.className = v;
        else if (k === 'id') el.id = v;
        else if (k.indexOf('data-') === 0) el.setAttribute(k, XSS.escapeAttr(v));
        else if (k === 'href' || k === 'src') el.setAttribute(k, XSS.sanitizeUrl(v));
        else el.setAttribute(k, XSS.escapeAttr(v));
      });
      if (textContent != null) el.textContent = textContent;
      return el;
    },

    /**
     * Set element text content (XSS-safe)
     */
    setText: function(el, text) {
      if (el) el.textContent = text == null ? '' : String(text);
    }
  };

  global.XSS = XSS;
})(window);
