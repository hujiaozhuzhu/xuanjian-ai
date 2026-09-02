/**
 * 玄鉴 RPC 桥接脚本
 *
 * 注入到目标页面中，建立与玄鉴 RPC 服务器的 WebSocket 通信
 * 支持远程函数调用、事件上报、自动重连
 */
(function() {
    'use strict';

    var WS_URL = 'ws://127.0.0.1:__PORT__/ws';
    var RECONNECT_INTERVAL = 3000;
    var MAX_RECONNECT_ATTEMPTS = 10;

    var ws = null;
    var callbacks = {};
    var msgId = 0;
    var reconnectAttempts = 0;
    var connected = false;

    function connect() {
        try {
            ws = new WebSocket(WS_URL);

            ws.onopen = function() {
                connected = true;
                reconnectAttempts = 0;
                console.log('[XuanJian] RPC bridge connected to ' + WS_URL);

                // 发送握手
                send({
                    type: 'handshake',
                    url: window.location.href,
                    title: document.title,
                    timestamp: Date.now()
                });
            };

            ws.onmessage = function(evt) {
                try {
                    var msg = JSON.parse(evt.data);
                    if (msg.id && callbacks[msg.id]) {
                        callbacks[msg.id](msg.result, msg.error);
                        delete callbacks[msg.id];
                    }
                } catch(e) {
                    console.error('[XuanJian] Message parse error:', e);
                }
            };

            ws.onclose = function() {
                connected = false;
                if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                    reconnectAttempts++;
                    setTimeout(connect, RECONNECT_INTERVAL);
                }
            };

            ws.onerror = function(err) {
                console.error('[XuanJian] WebSocket error:', err);
            };
        } catch(e) {
            console.error('[XuanJian] Connection error:', e);
        }
    }

    function send(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(data));
        }
    }

    // 公共 API
    window.__xuanjian_rpc__ = {
        /**
         * 调用远程方法
         */
        call: function(method, args) {
            return new Promise(function(resolve, reject) {
                var id = ++msgId;
                callbacks[id] = function(result, error) {
                    if (error) reject(new Error(error));
                    else resolve(result);
                };
                send({id: id, method: method, args: args || []});

                // 超时处理
                setTimeout(function() {
                    if (callbacks[id]) {
                        delete callbacks[id];
                        reject(new Error('RPC call timeout'));
                    }
                }, 30000);
            });
        },

        /**
         * 上报数据（无需响应）
         */
        report: function(data) {
            send({type: 'report', data: data});
        },

        /**
         * 检查连接状态
         */
        isConnected: function() {
            return connected;
        },

        /**
         * 获取连接信息
         */
        getInfo: function() {
            return {
                url: WS_URL,
                connected: connected,
                reconnectAttempts: reconnectAttempts
            };
        }
    };

    // 监听 Hook 事件并上报
    window.addEventListener('xuanjian_hook', function(e) {
        send({
            type: 'hook_event',
            data: e.detail
        });
    });

    // 连接
    connect();
})();
