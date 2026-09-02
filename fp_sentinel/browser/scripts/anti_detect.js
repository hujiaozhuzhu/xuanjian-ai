/**
 * 玄鉴反检测脚本
 *
 * 隐藏自动化浏览器的特征，防止被网站检测
 */
(function() {
    'use strict';

    // ─────────────────────── WebDriver 检测 ───────────────────────

    // 隐藏 webdriver 标志
    Object.defineProperty(navigator, 'webdriver', {
        get: function() { return undefined; },
        configurable: true
    });

    // 删除 window.navigator.webdriver
    delete navigator.__proto__.webdriver;

    // ─────────────────────── Chrome DevTools Protocol ───────────────────────

    // 创建 chrome 对象
    if (!window.chrome) {
        window.chrome = {};
    }
    if (!window.chrome.runtime) {
        window.chrome.runtime = {};
    }

    // ─────────────────────── Plugins ───────────────────────

    Object.defineProperty(navigator, 'plugins', {
        get: function() {
            return [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                { name: 'Native Client', filename: 'internal-nacl-plugin' }
            ];
        },
        configurable: true
    });

    Object.defineProperty(navigator, 'mimeTypes', {
        get: function() {
            return [
                { type: 'application/pdf', suffixes: 'pdf', description: '' },
                { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' }
            ];
        },
        configurable: true
    });

    // ─────────────────────── Languages ───────────────────────

    Object.defineProperty(navigator, 'languages', {
        get: function() { return ['zh-CN', 'zh', 'en-US', 'en']; },
        configurable: true
    });

    // ─────────────────────── Platform ───────────────────────

    Object.defineProperty(navigator, 'platform', {
        get: function() { return 'Win32'; },
        configurable: true
    });

    // ─────────────────────── Hardware Concurrency ───────────────────────

    Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: function() { return 8; },
        configurable: true
    });

    // ─────────────────────── Device Memory ───────────────────────

    Object.defineProperty(navigator, 'deviceMemory', {
        get: function() { return 8; },
        configurable: true
    }

    // ─────────────────────── Screen Resolution ───────────────────────

    Object.defineProperty(screen, 'availWidth', { get: function() { return 1920; } });
    Object.defineProperty(screen, 'availHeight', { get: function() { return 1080; } });
    Object.defineProperty(screen, 'width', { get: function() { return 1920; } });
    Object.defineProperty(screen, 'height', { get: function() { return 1080; } });
    Object.defineProperty(screen, 'colorDepth', { get: function() { return 24; } });

    // ─────────────────────── Permissions ───────────────────────

    var originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = function(parameters) {
        if (parameters.name === 'notifications') {
            return Promise.resolve({ state: Notification.permission });
        }
        return originalQuery(parameters);
    };

    // ─────────────────────── WebGL ───────────────────────

    var getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) {
            return 'Intel Inc.';
        }
        if (parameter === 37446) {
            return 'Intel(R) Iris(TM) Graphics 6100';
        }
        return getParameter.apply(this, arguments);
    };

    // ─────────────────────── Canvas 指纹 ───────────────────────

    var originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
        if (type === 'image/png' && this.width === 16 && this.height === 16) {
            // 可能是指纹检测
            var context = this.getContext('2d');
            if (context) {
                // 添加微小噪声
                var imageData = context.getImageData(0, 0, this.width, this.height);
                for (var i = 0; i < imageData.data.length; i += 4) {
                    imageData.data[i] = imageData.data[i] ^ 1;
                }
                context.putImageData(imageData, 0, 0);
            }
        }
        return originalToDataURL.apply(this, arguments);
    };

    // ─────────────────────── Audio 指纹 ───────────────────────

    var originalCreateOscillator = AudioContext.prototype.createOscillator;
    AudioContext.prototype.createOscillator = function() {
        var oscillator = originalCreateOscillator.apply(this, arguments);
        var originalConnect = oscillator.connect;
        oscillator.connect = function() {
            return originalConnect.apply(this, arguments);
        };
        return oscillator;
    };

    // ─────────────────────── 时间戳 ───────────────────────

    // 防止 performance.now() 检测
    var originalPerformanceNow = performance.now;
    var timeOffset = Math.random() * 10;
    performance.now = function() {
        return originalPerformanceNow.call(performance) + timeOffset;
    };

    console.log('[XuanJian] Anti-detect scripts installed');
})();
