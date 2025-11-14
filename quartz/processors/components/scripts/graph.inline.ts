export default () => {
  async function initGraphOnce() {
    try {
      const resp = await fetch('/graph.json', { cache: 'no-store' })
      if (!resp.ok) return
      const data = await resp.json()
      const container = document.querySelector('.graph-container')
      if (!container) return
      container.innerHTML = ''
      // Render simple circular SVG graph
      const svgNS = 'http://www.w3.org/2000/svg'
      const svg = document.createElementNS(svgNS, 'svg')
      svg.setAttribute('width', '100%')
      svg.setAttribute('height', '400')
      container.appendChild(svg)
      const entries = Object.entries(data)
      const n = Math.min(entries.length, 40)
      const cx = 400, cy = 200, r = Math.min(160, (window.innerWidth||800)/4)
      for (let i=0;i<n;i++) {
        const [id, item] = entries[i]
        const theta = (i / n) * Math.PI * 2
        const x = cx + r * Math.cos(theta)
        const y = cy + r * Math.sin(theta)
        const circle = document.createElementNS(svgNS, 'circle')
        circle.setAttribute('cx', String(x))
        circle.setAttribute('cy', String(y))
        circle.setAttribute('r', '8')
        circle.setAttribute('fill', 'var(--secondary)')
        circle.style.cursor = 'pointer'
        circle.addEventListener('click', () => {
          if (window.spaNavigate) window.spaNavigate(new URL(id, window.location.toString()))
          else window.location.href = id
        })
        svg.appendChild(circle)
        const txt = document.createElementNS(svgNS, 'text')
        txt.setAttribute('x', String(x + 12))
        txt.setAttribute('y', String(y + 4))
        txt.setAttribute('font-size', '12')
        txt.setAttribute('fill', 'var(--dark)')
        txt.textContent = (item.title || id).slice(0,24)
        svg.appendChild(txt)
      }
    } catch (e) {
      console.error('graph init failed', e)
    }
  }
  document.addEventListener('nav', initGraphOnce)
  initGraphOnce()
}
