import { QuartzComponent, QuartzComponentConstructor } from "./types"
import { useEffect, useState } from "preact/hooks"
import { classNames } from "../util/lang"
import "../components/styles/graphToggle.scss"

export default (() => {
  const GraphToggle: QuartzComponent = () => {
    const [open, setOpen] = useState(false)

    useEffect(() => {
      const graphContainer = document.querySelector(".graph-container")
      if (graphContainer) {
        graphContainer.classList.toggle("hidden", !open)
      }
    }, [open])

    return (
      <div class="graph-toggle-wrapper">
        <button class="graph-toggle-btn" onClick={() => setOpen(!open)}>
          {open ? "Hide Graph" : "View Graph"}
        </button>
      </div>
    )
  }

  return GraphToggle
}) satisfies QuartzComponentConstructor
