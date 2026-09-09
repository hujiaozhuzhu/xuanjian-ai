/**
 * XuanJian v3.1 - Event Stream Manager
 * WebSocket with auto-reconnect + polling fallback
 * Recon backoff: 1s, 2s, 4s, 8s, max 30s
 * After 3 failures, degrade to polling (5s interval)
 */
(function (global) {
  'use strict';

  var EventStream = {
    _ws: null,
    _status: 'disconnected', // connected | disconnected | polling
    _reconnectAttempts: 0,
    _maxReconnectAttempts: 3,
    _reconnectDelay: 1000,
    _maxReconnectDelay: 30000,
    _pollingTimer: null,
    _pollingInterval: 5000,
    _listeners: {},
    _scanId: null,

    /**
     * Initialize event stream for a scan
     */
    connect: function(scanId) {
      this._scanId = scanId;
      this._reconnectAttempts = 0;
      this._reconnectDelay = 1000;
      this._cleanup();
      this._tryWebSocket();
    },

    /**
     * Disconnect from all streams
     */
    disconnect: function() {
      this._cleanup();
      this._setStatus('disconnected');
    },

    /**
     * Get current connection status
     */
    getStatus: function() {
      return this._status;
    },

    /**
     * Subscribe to event type
     */
    on: function(type, callback) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push(callback);
    },

    /**
     * Unsubscribe from event type
     */
    off: function(type, callback) {
      if (!this._listeners[type]) return;
      this._listeners[type] = this._listeners[type].filter(function(cb) { return cb !== callback; });
    },

    // ── Private ──

    _tryWebSocket: function() {
      var self = this;
      if (!this._scanId) return;

      try {
        var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var wsUrl = protocol + '//' + location.host + '/ws/scan/' + this._scanId;

        this._ws = new WebSocket(wsUrl);

        this._ws.onopen = function() {
          self._reconnectAttempts = 0;
          self._reconnectDelay = 1000;
          self._clearPolling();
          self._setStatus('connected');
        };

        this._ws.onmessage = function(event) {
          try {
            var data = JSON.parse(event.data);
            self._emit(data.type, data);
            self._emit('*', data);
          } catch (e) {
            console.warn('[EventStream] WS message parse error:', e);
          }
        };

        this._ws.onclose = function() {
          self._attemptReconnect();
        };

        this._ws.onerror = function() {
          if (self._ws) self._ws.close();
        };
      } catch (e) {
        console.warn('[EventStream] WebSocket init failed:', e);
        this._attemptReconnect();
      }
    },

    _attemptReconnect: function() {
      if (this._reconnectAttempts >= this._maxReconnectAttempts) {
        console.warn('[EventStream] Max reconnect attempts reached, falling back to polling');
        this._startPolling();
        return;
      }
      this._reconnectAttempts++;
      this._setStatus('disconnected');

      var self = this;
      var delay = Math.min(this._reconnectDelay * Math.pow(2, this._reconnectAttempts - 1), this._maxReconnectDelay);
      console.log('[EventStream] Reconnecting in ' + delay + 'ms (attempt ' + this._reconnectAttempts + ')');

      setTimeout(function() { self._tryWebSocket(); }, delay);
    },

    _startPolling: function() {
      var self = this;
      this._setStatus('polling');
      this._clearPolling();

      function poll() {
        if (!self._scanId) return;
        fetch('/api/v1/scans/' + encodeURIComponent(self._scanId))
          .then(function(r) { return r.ok ? r.json() : null; })
          .then(function(data) {
            if (data) {
              self._emit('poll', data);
              self._emit('*', { type: 'poll', data: data });
              if (data.status === 'completed' || data.status === 'failed') {
                self._emit('completed', data);
                self._clearPolling();
              }
            }
          })
          .catch(function() {});
      }

      poll();
      this._pollingTimer = setInterval(poll, this._pollingInterval);
    },

    _clearPolling: function() {
      if (this._pollingTimer) {
        clearInterval(this._pollingTimer);
        this._pollingTimer = null;
      }
    },

    _cleanup: function() {
      this._clearPolling();
      if (this._ws) {
        this._ws.onopen = null;
        this._ws.onclose = null;
        this._ws.onerror = null;
        this._ws.onmessage = null;
        try { this._ws.close(); } catch (e) {}
        this._ws = null;
      }
    },

    _setStatus: function(status) {
      if (this._status === status) return;
      this._status = status;
      var dot = document.getElementById('xj-ws-dot');
      var label = document.getElementById('xj-ws-label');
      if (dot) {
        dot.className = 'xj-ws-dot ' + status;
      }
      if (label) {
        var labels = { connected: '实时连接', disconnected: '未连接', polling: '降级轮询' };
        label.textContent = labels[status] || status;
      }
      this._emit('status', status);
    },

    _emit: function(type, data) {
      if (this._listeners[type]) {
        this._listeners[type].forEach(function(cb) {
          try { cb(data); } catch (e) { console.error('[EventStream] Listener error:', e); }
        });
      }
    }
  };

  global.EventStream = EventStream;
})(window);
