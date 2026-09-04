/**
 * 玄鉴 XHR/Fetch Hook 脚本
 *
 * 监控 XMLHttpRequest 和 Fetch 请求
 */
(function() {
    'use strict';

    var requestLog = [];

    function report(type, data) {
        var entry = {
            type: type,
            data: data,
            url: window.location.href,
            timestamp: Date.now()
        };
        requestLog.push(entry);

        window.dispatchEvent(new CustomEvent('xuanjian_hook', {
            detail: {
                type: 'request_' + type,
                target: data.url || 'unknown',
                data: entry
            }
        }));
    }

    // ─────────────────────── XMLHttpRequest Hook ───────────────────────

    var XHR = XMLHttpRequest.prototype;
    var open = XHR.open;
    var send = XHR.send;
    var setRequestHeader = XHR.setRequestHeader;

    XHR.open = function(method, url) {
        this._xuanjian = {
            method: method,
            url: url,
            headers: {},
            startTime: Date.now()
        };
        return open.apply(this, arguments);
    };

    XHR.setRequestHeader = function(name, value) {
        if (this._xuanjian) {
            this._xuanjian.headers[name] = value;
        }
        return setRequestHeader.apply(this, arguments);
    };

    XHR.send = function(postData) {
        var self = this;
        if (this._xuanjian) {
            this._xuanjian.requestBody = postData;

            this.addEventListener('load', function() {
                var duration = Date.now() - self._xuanjian.startTime;
                report('xhr', {
                    method: self._xuanjian.method,
                    url: self._xuanjian.url,
                    status: self.status,
                    duration: duration,
                    headers: self._xuanjian.headers,
                    requestBody: self._xuanjian.requestBody ?
                        (typeof self._xuanjian.requestBody === 'string' ?
                            self._xuanjian.requestBody.substring(0, 500) : '[Binary]') : null,
                    responseHeaders: self.getAllResponseHeaders()
                });
            });

            this.addEventListener('error', function() {
                report('xhr_error', {
                    method: self._xuanjian.method,
                    url: self._xuanjian.url,
                    duration: Date.now() - self._xuanjian.startTime
                });
            });
        }

        return send.apply(this, arguments);
    };

    // ─────────────────────── Fetch Hook ───────────────────────

    var originalFetch = window.fetch;

    window.fetch = function(input, init) {
        var url = typeof input === 'string' ? input : input.url;
        var method = (init && init.method) || 'GET';
        var startTime = Date.now();

        return originalFetch.apply(this, arguments).then(function(response) {
            var duration = Date.now() - startTime;

            report('fetch', {
                method: method,
                url: url,
                status: response.status,
                duration: duration,
                requestBody: init && init.body ?
                    (typeof init.body === 'string' ? init.body.substring(0, 500) : '[Binary]') : null,
                headers: init && init.headers ? JSON.stringify(init.headers) : null
            });

            return response;
        }).catch(function(error) {
            report('fetch_error', {
                method: method,
                url: url,
                error: error.message,
                duration: Date.now() - startTime
            });
            throw error;
        });
    };

    // 导出日志
    window.__xuanjian_requests__ = {
        getLog: function() { return requestLog; },
        clear: function() { requestLog = []; }
    };

    console.log('[XuanJian] XHR/Fetch hooks installed');
})();
