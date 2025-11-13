export default () => {
  const tocButton = document.getElementById("toggle-toc")
  const tocSection = document.getElementById("toc-section")

  if (tocButton && tocSection) {
    tocButton.addEventListener("click", () => {
      tocSection.classList.toggle("collapsed")
    })
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      const slug = entry.target.id
      const tocLinks = document.querySelectorAll(`a[data-for="${slug}"]`)
      tocLinks.forEach((link) =>
        entry.isIntersecting
          ? link.classList.add("in-view")
          : link.classList.remove("in-view")
      )
    })
  })

  document.querySelectorAll("h1[id], h2[id], h3[id]").forEach((el) => observer.observe(el))
}
