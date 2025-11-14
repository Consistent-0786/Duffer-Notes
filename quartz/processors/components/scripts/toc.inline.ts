export default () => {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      const slug = entry.target.id
      const tocLinks = document.querySelectorAll(`a[data-for="${slug}"]`)
      tocLinks.forEach((link) => {
        if (entry.isIntersecting) link.classList.add("in-view")
        else link.classList.remove("in-view")
      })
    }
  }, { root: null, rootMargin: "0px 0px -60% 0px", threshold: [0, 0.1, 0.5, 1] })
  document.querySelectorAll("h1[id], h2[id], h3[id], h4[id]").forEach((el) => observer.observe(el))
}
