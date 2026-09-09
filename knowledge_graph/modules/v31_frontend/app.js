/**
 * XuanJian v3.1 - Application Entry Point
 * Initializes SPA: register routes, build nav, start router
 */
(function () {
  'use strict';

  function init() {
    // Register all routes
    if (typeof XJPages !== 'undefined') {
      XJPages.register();
    }

    // Build navigation
    buildNavigation();

    // Initialize hash router
    if (typeof Router !== 'undefined') {
      Router.init();
    }

    // Global Esc key closes modal
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        UI.closeModal();
      }
    });

    // Click on app logo goes to dashboard
    var logo = document.getElementById('xj-logo');
    if (logo) {
      logo.onclick = function() { Router.navigate('/dashboard'); };
    }

    console.log('[XuanJian v3.1] Frontend initialized - Zero-build SPA ready');
  }

  function buildNavigation() {
    var nav = document.getElementById('xj-nav');
    if (!nav || typeof Router === 'undefined') return;

    // Get routes and organize by group
    var routes = Router.getRoutes();
    var groups = {
      core: { label: '审计中心', routes: [] },
      v3: { label: 'v3 能力', routes: [] }
    };

    var groupMap = {
      '/dashboard': 'core',
      '/scan': 'core',
      '/findings': 'core',
      '/profile': 'core',
      '/reports': 'core',
      '/settings': 'core',
      '/ai-pentest': 'v3',
      '/auto-fix': 'v3',
      '/benchmark': 'v3',
      '/privacy': 'v3',
      '/devsecops': 'v3'
    };

    var groupLabels = {
      core: { label: '审计中心', icon: '◆' },
      v3: { label: 'AI 能力', icon: '✦' }
    };

    var groupMembers = { core: [], v3: [] };

    routes.forEach(function(r) {
      var grp = groupMap[r.path] || 'core';
      groupMembers[grp].push(r);
    });

    // Render nav groups
    Object.keys(groupMembers).forEach(function(grpKey) {
      var members = groupMembers[grpKey];
      if (members.length === 0) return;

      if (members.length === 1) {
        // Single item - render as nav item directly
        var r = members[0];
        var item = document.createElement('button');
        item.className = 'xj-nav-item';
        item.setAttribute('data-route', r.path);
        item.textContent = r.config.navLabel || r.config.title;
        item.onclick = function() { Router.navigate(r.path); };
        nav.appendChild(item);
      } else {
        // Group - render as dropdown
        var groupEl = document.createElement('div');
        groupEl.className = 'xj-nav-group';

        var labelEl = document.createElement('span');
        labelEl.className = 'xj-nav-group-label';
        labelEl.innerHTML = '<span>' + (groupLabels[grpKey] ? groupLabels[grpKey].icon : '') + '</span> ' + (groupLabels[grpKey] ? groupLabels[grpKey].label : grpKey);

        var menuEl = document.createElement('div');
        menuEl.className = 'xj-nav-group-menu';

        members.forEach(function(r) {
          var subItem = document.createElement('button');
          subItem.className = 'xj-nav-item';
          subItem.setAttribute('data-route', r.path);
          subItem.textContent = r.config.navLabel || r.config.title;
          subItem.onclick = function() { Router.navigate(r.path); };
          menuEl.appendChild(subItem);
        });

        groupEl.appendChild(labelEl);
        groupEl.appendChild(menuEl);
        nav.appendChild(groupEl);
      }
    });
  }

  // Wait for DOM + all script tags
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
