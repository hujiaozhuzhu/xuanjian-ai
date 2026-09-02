/**
 * 玄鉴 Cookie Hook 脚本
 *
 * 监控 Cookie 的读写操作
 */
(function() {
    'use strict';

    var cookieLog = [];

    function report(action, data) {
        var entry = {
            action: action,
            data: data,
            url: window.location.href,
            timestamp: Date.now()
        };
        cookieLog.push(entry);

        window.dispatchEvent(new CustomEvent('xuanjian_hook', {
            detail: {
                type: 'cookie_' + action,
                target: 'document.cookie',
                data: entry
            }
        }));
    }

    // Hook document.cookie 的 setter
    var originalCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                         Object.getOwnPropertyDescriptor(document, 'cookie');

    if (originalCookie && originalCookie.set) {
        Object.defineProperty(document, 'cookie', {
            get: function() {
                return originalCookie.get.call(document);
            },
            set: function(value) {
                // 解析 cookie 信息
                var parts = value.split(';')[0].split('=');
                var name = parts[0] ? parts[0].trim() : '';
                var cookieValue = parts[1] ? parts[1].trim() : '';

                report('set', {
                    name: name,
                    value: cookieValue.length > 50 ? cookieValue.substring(0, 50) + '...' : cookieValue,
                    full: value.substring(0, 200),
                    httpOnly: value.toLowerCase().includes('httponly'),
                    secure: value.toLowerCase().includes('secure'),
                    sameSite: (value.match(/samesite=(\w+)/i) || [])[1] || null
                });

                return originalCookie.set.call(document, value);
            },
            configurable: true
        });
    }

    // 导出日志
    window.__xuanjian_cookies__ = {
        getLog: function() { return cookieLog; },
        clear: function() { cookieLog = []; }
    };

    console.log('[XuanJian] Cookie hooks installed');
})();
