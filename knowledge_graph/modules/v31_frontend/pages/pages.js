/**
 * XuanJian v3.1 - Page Registry
 * Collects all page registrations and registers them with Router
 */
(function (global) {
  'use strict';

  var pages = [];

  function add(pageCfg) {
    pages.push(pageCfg);
  }

  function register() {
    if (typeof Router === 'undefined') {
      console.error('[Pages] Router not available');
      return;
    }
    pages.forEach(function(p) {
      Router.register(p.path, {
        title: p.title || p.navLabel,
        render: p.render,
        navLabel: p.navLabel,
        onEnter: p.onEnter
      });
    });
  }

  global.XJPages = { add: add, register: register };
})(window);
