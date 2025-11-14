export default () => {
  const toggleButton = document.getElementById("toggle-graph")
  const graphSection = document.getElementById("graph-section")

  if (toggleButton && graphSection) {
    toggleButton.addEventListener("click", () => {
      graphSection.classList.toggle("collapsed")
    })
  }
}
