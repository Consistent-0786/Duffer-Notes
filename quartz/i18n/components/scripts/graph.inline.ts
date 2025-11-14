
export default () => {
  function createSVG(width, height) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', width);
    svg.setAttribute('height', height);
    svg.style.display = 'block';
    return svg;
  }

  function renderSimpleGraph(container, data) {
    // Data is expected to be an object mapping slug -> { title?, links?: [], tags?: [] }
    const entries = Object.entries(data);
    if (entries.length === 0) {
      container.textContent = 'No graph data available';
      return;
    }

    const nodes = entries.map(([id, details]) => ({ id, title: details.title ?? id }));
    const validIds = new Set(nodes.map(n => n.id));
    const links = [];
    for (const [id, details] of entries) {
      const outgoing = details.links ?? [];
      for (const dest of outgoing) {
        if (validIds.has(dest)) links.push({ source: id, target: dest });
      }
    }

    const width = container.clientWidth || 600;
    const height = Math.max(container.clientHeight, 400);
    container.innerHTML = '';
    const svg = createSVG(width, height);
    container.appendChild(svg);

    // simple circular layout
    const cx = width / 2;
    const cy = height / 2;
    const r = Math.min(width, height) / 2 - 40;
    const thetaStep = (Math.PI * 2) / nodes.length;
    const positions = {};
    nodes.forEach((n, i) => {
      const theta = i * thetaStep;
      positions[n.id] = { x: cx + r * Math.cos(theta), y: cy + r * Math.sin(theta) };
    });

    // draw links
    for (const l of links) {
      const s = positions[l.source];
      const t = positions[l.target];
      const line = document.createElementNS(svg.namespaceURI, 'line');
      line.setAttribute('x1', String(s.x));
      line.setAttribute('y1', String(s.y));
      line.setAttribute('x2', String(t.x));
      line.setAttribute('y2', String(t.y));
      line.setAttribute('stroke', 'var(--lightgray, #bbb)');
      line.setAttribute('stroke-width', '1');
      svg.appendChild(line);
    }

    // draw nodes
    for (const n of nodes) {
      const p = positions[n.id];
      const g = document.createElementNS(svg.namespaceURI, 'g');
      g.setAttribute('transform', `translate(${p.x}, ${p.y})`);
      const circle = document.createElementNS(svg.namespaceURI, 'circle');
      circle.setAttribute('r', '8');
      circle.setAttribute('fill', 'var(--secondary, #284b63)');
      circle.style.cursor = 'pointer';

      circle.addEventListener('click', () => {
        // navigate to node slug
        const url = new URL(n.id, window.location.toString());
        // Quartz uses spaNavigate
        if ((window as any).spaNavigate) {
          (window as any).spaNavigate(url);
        } else {
          window.location.href = url.toString();
        }
      });

      const text = document.createElementNS(svg.namespaceURI, 'text');
      text.setAttribute('x', '12');
      text.setAttribute('y', '4');
      text.setAttribute('font-size', '12');
      text.setAttribute('fill', 'var(--dark, #222)');
      text.textContent = n.title;

      g.appendChild(circle);
      g.appendChild(text);
      svg.appendChild(g);
    }
  }

  async function initGraph() {
    try {
      const resp = await fetch('/graph.json', {cache: 'no-store'});
      if (!resp.ok) {
        console.warn('could not load /graph.json', resp.status);
        return;
      }
      const data = await resp.json();
      const containers = document.querySelectorAll('.graph-container, .local-graph, .global-graph, .graph-local, .graph-global');
      containers.forEach((c) => {
        renderSimpleGraph(c, data);
      });
    } catch (e) {
      console.error('graph init error', e);
    }
  }

  // toggle button behavior (if present)
  const toggleButton = document.getElementById('toggle-graph');
  const graphSection = document.getElementById('graph-section');
  if (toggleButton && graphSection) {
    toggleButton.addEventListener('click', () => {
      graphSection.classList.toggle('collapsed');
    });
  }

  // run on nav and on startup
  document.addEventListener('nav', () => {
    initGraph();
  });
  // also run immediately
  initGraph();
}
