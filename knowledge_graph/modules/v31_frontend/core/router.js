/**
 * XuanJian v3.1 - Hash Router
 * Lightweight SPA router with hash-based navigation
 */
(function (global) {
  'use strict';

  var routes = {};
  var currentRoute = null;
  var currentParams = {};
  var beforeHooks = [];
  var afterHooks = [];

  var Router = {
    /**
     * Register a route
     * @param {string} path - Route path (e.g. '/dashboard', '/findings/:id')
     * @param {object} config - { title, render, onEnter, navGroup }
     */
    register: function(path, config) {
      var paramNames = [];
      var regexPath = path.replace(/:([^\/]+)/g, function(_, name) {
        paramNames.push(name);
        return '([^/]+)';
      });
      routes[path] = {
        path: path,
        regex: new RegExp('^' + regexPath + '$'),
        paramNames: paramNames,
        config: config
      };
    },

    /**
     * Add a before hook
     */
    before: function(hook) { beforeHooks.push(hook); },

    /**
     * Add an after hook
     */
    after: function(hook) { afterHooks.push(hook); },

    /**
     * Navigate to a path
     */
    navigate: function(path) {
      location.hash = path;
    },

    /**
     * Initialize the router
     */
    init: function() {
      var self = this;
      window.addEventListener('hashchange', function() { self._handleChange(); });
      // Handle initial load
      if (!location.hash) {
        location.hash = '#/dashboard';
      } else {
        self._handleChange();
      }
    },

    /**
     * Get current route info
     */
    getCurrent: function() {
      return { route: currentRoute, params: currentParams };
    },

    /**
     * Get all registered routes
     */
    getRoutes: function() {
      return Object.keys(routes).map(function(k) { return routes[k]; });
    },

    // ── Private ──

    _handleChange: function() {
      var hash = location.hash || '#/dashboard';
      var path = hash.replace(/^#/, '');
      var self = this;

      // Run before hooks
      var cancelled = false;
      beforeHooks.forEach(function(hook) {
        if (!cancelled) {
          var result = hook(path, currentRoute);
          if (result === false) cancelled = true;
        }
      });

      if (cancelled) return;

      // Match route
      var matched = this._match(path);
      if (!matched) {
        // Fallback to dashboard
        location.hash = '#/dashboard';
        return;
      }

      currentRoute = matched.route;
      currentParams = matched.params;

      // Update nav active state
      this._updateNav(matched.route.path);

      // Update document title
      if (matched.route.config.title) {
        document.title = matched.route.config.title + ' - 玄鉴 XuanJian v3.1';
      }

      // Call render
      if (matched.route.config.render) {
        try {
          matched.route.config.render(matched.params, currentParams);
        } catch (e) {
          console.error('[Router] Render error for', matched.route.path, e);
        }
      }

      // Call onEnter
      if (matched.route.config.onEnter) {
        try {
          matched.route.config.onEnter(matched.params, currentParams);
        } catch (e) {
          console.error('[Router] onEnter error for', matched.route.path, e);
        }
      }

      // Run after hooks
      afterHooks.forEach(function(hook) {
        hook(matched.route, currentRoute);
      });
    },

    _match: function(path) {
      var keys = Object.keys(routes);
      for (var i = 0; i < keys.length; i++) {
        var route = routes[keys[i]];
        var match = path.match(route.regex);
        if (match) {
          var params = {};
          route.paramNames.forEach(function(name, idx) {
            params[name] = decodeURIComponent(match[idx + 1]);
          });
          return { route: route, params: params };
        }
      }
      return null;
    },

    _updateNav: function(activePath) {
      var items = document.querySelectorAll('.xj-nav-item[data-route]');
      items.forEach(function(el) {
        if (el.getAttribute('data-route') === activePath) {
          el.classList.add('active');
        } else {
          el.classList.remove('active');
        }
      });
    }
  };

  global.Router = Router;
})(window);
