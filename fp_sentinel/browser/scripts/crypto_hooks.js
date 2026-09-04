/**
 * 玄鉴加解密 Hook 脚本
 *
 * 自动 Hook 常见加密库，捕获密钥和加密操作:
 * - Web Crypto API
 * - CryptoJS
 * - JSEncrypt (RSA)
 * - forge
 * - tweetnacl
 */
(function() {
    'use strict';

    var captured = {
        keys: [],
        operations: [],
        startTime: Date.now()
    };

    function report(type, data) {
        data.timestamp = Date.now();
        data.pageUrl = window.location.href;

        if (type === 'key') {
            captured.keys.push(data);
        } else {
            captured.operations.push(data);
        }

        window.dispatchEvent(new CustomEvent('xuanjian_hook', {
            detail: {
                type: 'crypto_' + type,
                target: data.algorithm || data.lib || 'unknown',
                data: data
            }
        }));
    }

    // ─────────────────────── Web Crypto API ───────────────────────

    if (window.crypto && window.crypto.subtle) {
        var _importKey = crypto.subtle.importKey.bind(crypto.subtle);
        crypto.subtle.importKey = function() {
            var args = Array.from(arguments);
            report('key', {
                action: 'import',
                format: args[0],
                algorithm: args[1] ? args[1].name : 'unknown',
                lib: 'WebCrypto'
            });
            return _importKey.apply(this, arguments);
        };

        var _generateKey = crypto.subtle.generateKey.bind(crypto.subtle);
        crypto.subtle.generateKey = function() {
            var args = Array.from(arguments);
            report('key', {
                action: 'generate',
                algorithm: args[0] ? args[0].name : 'unknown',
                lib: 'WebCrypto'
            });
            return _generateKey.apply(this, arguments);
        };

        var _encrypt = crypto.subtle.encrypt.bind(crypto.subtle);
        crypto.subtle.encrypt = function() {
            var args = Array.from(arguments);
            report('operation', {
                action: 'encrypt',
                algorithm: args[0] ? args[0].name : 'unknown',
                lib: 'WebCrypto'
            });
            return _encrypt.apply(this, arguments);
        };

        var _decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
        crypto.subtle.decrypt = function() {
            var args = Array.from(arguments);
            report('operation', {
                action: 'decrypt',
                algorithm: args[0] ? args[0].name : 'unknown',
                lib: 'WebCrypto'
            });
            return _decrypt.apply(this, arguments);
        };

        var _sign = crypto.subtle.sign.bind(crypto.subtle);
        crypto.subtle.sign = function() {
            var args = Array.from(arguments);
            report('operation', {
                action: 'sign',
                algorithm: args[0] ? args[0].name : 'unknown',
                lib: 'WebCrypto'
            });
            return _sign.apply(this, arguments);
        };

        var _verify = crypto.subtle.verify.bind(crypto.subtle);
        crypto.subtle.verify = function() {
            var args = Array.from(arguments);
            report('operation', {
                action: 'verify',
                algorithm: args[0] ? args[0].name : 'unknown',
                lib: 'WebCrypto'
            });
            return _verify.apply(this, arguments);
        };
    }

    // ─────────────────────── CryptoJS ───────────────────────

    function hookCryptoJS() {
        if (typeof CryptoJS === 'undefined') return;

        // AES
        if (CryptoJS.AES) {
            var _aesEncrypt = CryptoJS.AES.encrypt;
            CryptoJS.AES.encrypt = function() {
                report('operation', { action: 'aes_encrypt', lib: 'CryptoJS' });
                return _aesEncrypt.apply(this, arguments);
            };

            var _aesDecrypt = CryptoJS.AES.decrypt;
            CryptoJS.AES.decrypt = function() {
                report('operation', { action: 'aes_decrypt', lib: 'CryptoJS' });
                return _aesDecrypt.apply(this, arguments);
            };
        }

        // DES/3DES
        ['DES', 'TripleDES'].forEach(function(algo) {
            if (CryptoJS[algo]) {
                var _encrypt = CryptoJS[algo].encrypt;
                CryptoJS[algo].encrypt = function() {
                    report('operation', { action: algo.toLowerCase() + '_encrypt', lib: 'CryptoJS' });
                    return _encrypt.apply(this, arguments);
                };
            }
        });

        // MD5/SHA
        ['MD5', 'SHA1', 'SHA256', 'SHA512'].forEach(function(algo) {
            if (CryptoJS[algo]) {
                var _hash = CryptoJS[algo];
                CryptoJS[algo] = function() {
                    report('operation', { action: algo.toLowerCase() + '_hash', lib: 'CryptoJS' });
                    return _hash.apply(this, arguments);
                };
            }
        });
    }

    // ─────────────────────── JSEncrypt (RSA) ───────────────────────

    function hookJSEncrypt() {
        if (typeof JSEncrypt === 'undefined') return;

        var _setPublicKey = JSEncrypt.prototype.setPublicKey;
        JSEncrypt.prototype.setPublicKey = function(key) {
            report('key', {
                action: 'rsa_set_public_key',
                keyPreview: key ? key.substring(0, 50) + '...' : 'null',
                lib: 'JSEncrypt'
            });
            return _setPublicKey.call(this, key);
        };

        var _setPrivateKey = JSEncrypt.prototype.setPrivateKey;
        JSEncrypt.prototype.setPrivateKey = function(key) {
            report('key', {
                action: 'rsa_set_private_key',
                keyPreview: key ? key.substring(0, 50) + '...' : 'null',
                lib: 'JSEncrypt'
            });
            return _setPrivateKey.call(this, key);
        };

        var _encrypt = JSEncrypt.prototype.encrypt;
        JSEncrypt.prototype.encrypt = function(data) {
            report('operation', { action: 'rsa_encrypt', lib: 'JSEncrypt' });
            return _encrypt.call(this, data);
        };

        var _decrypt = JSEncrypt.prototype.decrypt;
        JSEncrypt.prototype.decrypt = function(data) {
            report('operation', { action: 'rsa_decrypt', lib: 'JSEncrypt' });
            return _decrypt.call(this, data);
        };
    }

    // ─────────────────────── forge ───────────────────────

    function hookForge() {
        if (typeof forge === 'undefined') return;

        if (forge.cipher && forge.cipher.createCipher) {
            var _createCipher = forge.cipher.createCipher;
            forge.cipher.createCipher = function() {
                report('operation', { action: 'cipher_create', algorithm: arguments[0], lib: 'forge' });
                return _createCipher.apply(this, arguments);
            };
        }

        if (forge.cipher && forge.cipher.createDecipher) {
            var _createDecipher = forge.cipher.createDecipher;
            forge.cipher.createDecipher = function() {
                report('operation', { action: 'decipher_create', algorithm: arguments[0], lib: 'forge' });
                return _createDecipher.apply(this, arguments);
            };
        }
    }

    // ─────────────────────── 初始化 ───────────────────────

    // 立即尝试 Hook 已加载的库
    hookCryptoJS();
    hookJSEncrypt();
    hookForge();

    // 延迟重试（等待异步加载的库）
    setTimeout(function() {
        hookCryptoJS();
        hookJSEncrypt();
        hookForge();
    }, 2000);

    setTimeout(function() {
        hookCryptoJS();
        hookJSEncrypt();
        hookForge();
    }, 5000);

    // 导出捕获的数据
    window.__xuanjian_crypto__ = {
        getKeys: function() { return captured.keys; },
        getOperations: function() { return captured.operations; },
        getAll: function() { return captured; },
        clear: function() {
            captured.keys = [];
            captured.operations = [];
        }
    };

    console.log('[XuanJian] Crypto hooks installed');
})();
