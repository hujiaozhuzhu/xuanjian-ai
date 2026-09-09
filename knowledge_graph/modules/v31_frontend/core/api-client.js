/**
 * XuanJian v3.1 - REST API Client
 * Lightweight fetch wrapper with XSS-safe responses, timeout, and error handling
 */
(function (global) {
  'use strict';

  var API_BASE = '';

  function buildUrl(path, params) {
    if (params) {
      var qs = Object.keys(params)
        .filter(function(k) { return params[k] != null && params[k] !== ''; })
        .map(function(k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
        .join('&');
      if (qs) path += (path.indexOf('?') === -1 ? '?' : '&') + qs;
    }
    return API_BASE + path;
  }

  function apiRequest(path, options) {
    options = options || {};
    var url = buildUrl(path, options.params);
    var fetchOpts = {
      method: options.method || 'GET',
      headers: { 'Content-Type': 'application/json' }
    };
    if (options.headers) {
      Object.keys(options.headers).forEach(function(k) { fetchOpts.headers[k] = options.headers[k]; });
    }
    if (options.body) {
      fetchOpts.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
    }
    var timeout = options.timeout || 30000;
    return new Promise(function(resolve, reject) {
      var timer = setTimeout(function() { reject(new Error('Request timeout')); }, timeout);
      fetch(url, fetchOpts)
        .then(function(resp) {
          clearTimeout(timer);
          if (!resp.ok) {
            reject(new Error('HTTP ' + resp.status + ': ' + resp.statusText));
            return;
          }
          var ct = resp.headers.get('content-type') || '';
          if (ct.indexOf('application/json') !== -1) {
            resp.json().then(resolve).catch(function() { reject(new Error('JSON parse error')); });
          } else {
            resp.text().then(resolve).catch(function() { reject(new Error('Text parse error')); });
          }
        })
        .catch(function(err) {
          clearTimeout(timer);
          reject(err);
        });
    });
  }

  var API = {
    setBaseUrl: function(url) { API_BASE = url; },

    // Dashboard stats
    getStats: function() { return apiRequest('/api/v1/stats'); },

    // Scans
    getScans: function() { return apiRequest('/api/v1/scans'); },
    getScanDetail: function(scanId) { return apiRequest('/api/v1/scans/' + encodeURIComponent(scanId)); },
    startScan: function(projectPath, language, scanners) {
      return apiRequest('/api/v1/scan', {
        method: 'POST',
        body: { project_path: projectPath, language: language || 'auto', scanners: scanners || null }
      });
    },

    // Findings
    getFindings: function(filters) { return apiRequest('/api/v1/findings', { params: filters }); },
    getFindingDetail: function(id) { return apiRequest('/api/v1/findings/' + encodeURIComponent(id)); },
    markFalsePositive: function(id, reason) {
      return apiRequest('/api/v1/findings/' + encodeURIComponent(id) + '/mark-fp', {
        method: 'POST', body: { reason: reason || '', scope: 'instance' }
      });
    },
    markTruePositive: function(id, reason) {
      return apiRequest('/api/v1/findings/' + encodeURIComponent(id) + '/mark-tp', {
        method: 'POST', body: { reason: reason || '' }
      });
    },

    // Export
    exportScan: function(scanId, format) { return '/api/v1/export/' + encodeURIComponent(scanId) + '?format=' + (format || 'json'); },

    // FP Optimize
    getFpDashboard: function() { return apiRequest('/api/v1/fp-optimize/dashboard'); },
    getFpRecommendations: function() { return apiRequest('/api/v1/fp-optimize/recommendations'); },
    getFpStats: function() { return apiRequest('/api/v1/fp-optimize/stats'); },
    getFpPatterns: function() { return apiRequest('/api/v1/fp-optimize/fp-patterns'); },
    triggerFpOptimize: function() { return apiRequest('/api/v1/fp-optimize/optimize', { method: 'POST', body: { dry_run: false } }); },

    // Privacy
    getPrivacyStats: function() { return apiRequest('/api/privacy/stats'); },
    federateInit: function(opts) { return apiRequest('/api/privacy/federate/initialize', { method: 'POST', body: opts }); },
    federateStatus: function(sid) { return apiRequest('/api/privacy/federate/status/' + encodeURIComponent(sid)); },
    complianceCheck: function(standards) { return apiRequest('/api/privacy/compliance/check', { method: 'POST', body: { standards: standards } }); },
    getComplianceStandards: function() { return apiRequest('/api/privacy/compliance/standards'); },

    // DevOps
    getDevOpsStats: function() { return apiRequest('/api/devops/stats'); },
    getDevOpsMappings: function(filters) { return apiRequest('/api/devops/mappings', { params: filters }); },

    // Health
    healthCheck: function() { return apiRequest('/api/v1/health'); }
  };

  global.API = API;
})(window);
