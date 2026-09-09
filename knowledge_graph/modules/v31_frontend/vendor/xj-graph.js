/**
 * XuanJian v3.1 - Graph Engine (Canvas-based, Cytoscape.js-like)
 * For attack chain visualization, network topology, node-link diagrams
 * Supports: force-directed layout, click/drag, zoom/pan, node states
 */
(function (global) {
  'use strict';

  function getDevicePixelRatio() {
    return window.devicePixelRatio || 1;
  }

  var Graph = {
    /**
     * Create a graph instance in a container
     * config: { nodes: [{ id, label, type, color, size, status }], edges: [{ source, target, label, color }] }
     */
    create: function(container, config) {
      var W = container.clientWidth || 800;
      var H = container.clientHeight || 400;

      var canvas = document.createElement('canvas');
      var dpr = getDevicePixelRatio();
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      canvas.style.width = W + 'px';
      canvas.style.height = H + 'px';
      container.innerHTML = '';
      container.appendChild(canvas);

      var ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);

      var nodes = (config.nodes || []).map(function(n) {
        return Object.assign({
          x: Math.random() * (W - 100) + 50,
          y: Math.random() * (H - 100) + 50,
          vx: 0, vy: 0,
          size: 28,
          label: n.id || '',
          color: '#58a6ff',
          borderColor: '#30363d',
          status: 'default' // default | active | success | warning | danger
        }, n);
      });

      var edges = (config.edges || []).map(function(e) {
        return Object.assign({ color: '#30363d', width: 1.5, label: '' }, e);
      });

      var instance = {
        canvas: canvas,
        ctx: ctx,
        width: W,
        height: H,
        nodes: nodes,
        edges: edges,
        transform: { x: 0, y: 0, scale: 1 },
        _dragging: null,
        _hovered: null,
        _running: false,
        _animFrame: null,
        _onClick: null,
        _onHover: null,
        _iterations: 0,
        _maxIterations: 200
      };

      // Initial layout
      _runLayout(instance);

      // Event handlers
      canvas.addEventListener('mousemove', function(e) { _handleMouseMove(e, instance); });
      canvas.addEventListener('mousedown', function(e) { _handleMouseDown(e, instance); });
      canvas.addEventListener('mouseup', function() { instance._dragging = null; });
      canvas.addEventListener('mouseleave', function() { instance._dragging = null; instance._hovered = null; _draw(instance); });
      canvas.addEventListener('click', function(e) { _handleClick(e, instance); });
      canvas.addEventListener('wheel', function(e) { _handleWheel(e, instance); }, { passive: false });

      _draw(instance);
      return instance;
    },

    /**
     * Update graph data
     */
    update: function(instance, config) {
      if (!instance) return;
      var oldNodes = {};
      instance.nodes.forEach(function(n) { oldNodes[n.id] = n; });
      instance.nodes = (config.nodes || []).map(function(n) {
        var existing = oldNodes[n.id];
        var merged = existing ? Object.assign({}, existing, n) : n;
        if (!existing && (!merged.x || !merged.y)) {
          merged.x = Math.random() * (instance.width - 100) + 50;
          merged.y = Math.random() * (instance.height - 100) + 50;
        }
        return Object.assign({
          vx: 0, vy: 0, size: 28, color: '#58a6ff', status: 'default'
        }, merged);
      });
      instance.edges = (config.edges || []).map(function(e) {
        return Object.assign({ color: '#30363d', width: 1.5, label: '' }, e);
      });
      instance._iterations = 0;
      _runLayout(instance);
    },

    /**
     * Set click handler
     */
    onClick: function(instance, handler) {
      if (instance) instance._onClick = handler;
    },

    /**
     * Stop animation and destroy
     */
    destroy: function(instance) {
      if (!instance) return;
      if (instance._animFrame) cancelAnimationFrame(instance._animFrame);
      instance._running = false;
      if (instance.canvas && instance.canvas.parentNode) {
        instance.canvas.parentNode.innerHTML = '';
      }
    }
  };

  // ── Layout ──
  function _runLayout(instance) {
    if (instance._running) return;
    instance._running = true;
    instance._iterations = 0;

    function tick() {
      if (instance._iterations >= instance._maxIterations && !instance._dragging) {
        instance._running = false;
        return;
      }
      instance._iterations++;
      _applyForces(instance);
      _draw(instance);
      instance._animFrame = requestAnimationFrame(tick);
    }
    tick();
  }

  function _applyForces(instance) {
    var nodes = instance.nodes;
    var edges = instance.edges;
    var k = 80; // ideal edge length
    var damping = 0.85;

    // Repulsive force between all nodes
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var dx = nodes[j].x - nodes[i].x;
        var dy = nodes[j].y - nodes[i].y;
        var dist = Math.sqrt(dx * dx + dy * dy) || 1;
        var force = (k * k) / dist;
        var fx = (dx / dist) * force;
        var fy = (dy / dist) * force;
        nodes[i].vx -= fx * 0.01;
        nodes[i].vy -= fy * 0.01;
        nodes[j].vx += fx * 0.01;
        nodes[j].vy += fy * 0.01;
      }
    }

    // Attractive force along edges
    edges.forEach(function(e) {
      var s = _findNode(nodes, e.source);
      var t = _findNode(nodes, e.target);
      if (!s || !t) return;
      var dx = t.x - s.x;
      var dy = t.y - s.y;
      var dist = Math.sqrt(dx * dx + dy * dy) || 1;
      var force = (dist * dist) / k;
      var fx = (dx / dist) * force;
      var fy = (dy / dist) * force;
      s.vx += fx * 0.01;
      s.vy += fy * 0.01;
      t.vx -= fx * 0.01;
      t.vy -= fy * 0.01;
    });

    // Center gravity
    var cx = instance.width / 2;
    var cy = instance.height / 2;
    nodes.forEach(function(n) {
      if (n === instance._dragging) return;
      n.vx += (cx - n.x) * 0.001;
      n.vy += (cy - n.y) * 0.001;
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
      // Clamp
      n.x = Math.max(n.size, Math.min(instance.width - n.size, n.x));
      n.y = Math.max(n.size, Math.min(instance.height - n.size, n.y));
    });
  }

  function _findNode(nodes, id) {
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].id === id) return nodes[i];
    }
    return null;
  }

  // ── Drawing ──
  function _draw(instance) {
    var ctx = instance.ctx;
    var w = instance.width;
    var h = instance.height;
    var t = instance.transform;
    ctx.clearRect(0, 0, w, h);
    ctx.save();
    ctx.translate(t.x, t.y);
    ctx.scale(t.scale, t.scale);

    // Draw edges
    instance.edges.forEach(function(e) {
      var s = _findNode(instance.nodes, e.source);
      var tg = _findNode(instance.nodes, e.target);
      if (!s || !tg) return;
      ctx.strokeStyle = e.color;
      ctx.lineWidth = e.width;
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(tg.x, tg.y);
      ctx.stroke();

      // Arrow head
      var dx = tg.x - s.x;
      var dy = tg.y - s.y;
      var dist = Math.sqrt(dx * dx + dy * dy) || 1;
      var angle = Math.atan2(dy, dx);
      var arrowX = tg.x - Math.cos(angle) * (tg.size + 2);
      var arrowY = tg.y - Math.sin(angle) * (tg.size + 2);
      ctx.fillStyle = e.color;
      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(arrowX - 8 * Math.cos(angle - 0.3), arrowY - 8 * Math.sin(angle - 0.3));
      ctx.lineTo(arrowX - 8 * Math.cos(angle + 0.3), arrowY - 8 * Math.sin(angle + 0.3));
      ctx.closePath();
      ctx.fill();

      // Edge label
      if (e.label) {
        var mx = (s.x + tg.x) / 2;
        var my = (s.y + tg.y) / 2;
        ctx.fillStyle = '#6e7681';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(e.label, mx, my - 4);
      }
    });

    // Draw nodes
    instance.nodes.forEach(function(n) {
      // Shadow / glow for active/warning/danger
      if (n.status === 'active' || n.status === 'danger' || n.status === 'success') {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.size + 4, 0, Math.PI * 2);
        var glowColor = n.status === 'danger' ? 'rgba(248,81,73,0.3)' : n.status === 'success' ? 'rgba(63,185,80,0.3)' : 'rgba(88,166,255,0.3)';
        ctx.fillStyle = glowColor;
        ctx.fill();
      }

      // Node body
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2);
      ctx.fillStyle = n.color;
      ctx.fill();
      ctx.strokeStyle = n._hovered ? '#e6edf3' : (n.borderColor || '#30363d');
      ctx.lineWidth = n._hovered ? 2.5 : 1.5;
      ctx.stroke();

      // Node label
      var label = n.label || n.id || '';
      ctx.fillStyle = '#fff';
      ctx.font = (n.size > 24 ? 'bold 11px' : '10px') + ' sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      if (label.length > 8) {
        ctx.fillText(label.slice(0, 8), n.x, n.y - 3);
        ctx.fillText('...', n.x, n.y + 8);
      } else {
        ctx.fillText(label, n.x, n.y);
      }
    });

    ctx.restore();
  }

  // ── Interaction ──
  function _getMousePos(e, instance) {
    var rect = instance.canvas.getBoundingClientRect();
    var t = instance.transform;
    return {
      x: (e.clientX - rect.left - t.x) / t.scale,
      y: (e.clientY - rect.top - t.y) / t.scale
    };
  }

  function _getNodeAt(x, y, instance) {
    for (var i = instance.nodes.length - 1; i >= 0; i--) {
      var n = instance.nodes[i];
      var dx = x - n.x;
      var dy = y - n.y;
      if (dx * dx + dy * dy <= n.size * n.size) return n;
    }
    return null;
  }

  function _handleMouseMove(e, instance) {
    var pos = _getMousePos(e, instance);
    var node = _getNodeAt(pos.x, pos.y, instance);

    if (instance._dragging) {
      instance._dragging.x = pos.x;
      instance._dragging.y = pos.y;
      instance._dragging.vx = 0;
      instance._dragging.vy = 0;
      if (!instance._running) {
        instance._iterations = 0;
        _runLayout(instance);
      }
      _draw(instance);
      return;
    }

    // Update hover state
    var changed = false;
    instance.nodes.forEach(function(n) {
      var wasHovered = n._hovered;
      n._hovered = (n === node);
      if (wasHovered !== n._hovered) changed = true;
    });

    if (changed) {
      instance.canvas.style.cursor = node ? 'pointer' : 'default';
      _draw(instance);
      if (instance._onHover) instance._onHover(node);
    }
  }

  function _handleMouseDown(e, instance) {
    var pos = _getMousePos(e, instance);
    var node = _getNodeAt(pos.x, pos.y, instance);
    if (node) {
      instance._dragging = node;
      instance.canvas.style.cursor = 'grabbing';
    }
  }

  function _handleClick(e, instance) {
    var pos = _getMousePos(e, instance);
    var node = _getNodeAt(pos.x, pos.y, instance);
    if (node && instance._onClick) {
      instance._onClick(node);
    }
  }

  function _handleWheel(e, instance) {
    e.preventDefault();
    var delta = e.deltaY > 0 ? 0.9 : 1.1;
    instance.transform.scale = Math.max(0.3, Math.min(3, instance.transform.scale * delta));
    _draw(instance);
    if (!instance._running) {
      instance._iterations = instance._maxIterations;
    }
  }

  global.Graph = Graph;
})(window);
