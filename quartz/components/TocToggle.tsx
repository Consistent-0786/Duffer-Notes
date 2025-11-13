import { QuartzComponent, QuartzComponentConstructor } from "./types"
import { useState, useEffect } from "preact/hooks"
import "../components/styles/tocToggle.scss"

export default (() => {
  const TocToggle: QuartzComponent = () => {
    const [open, setOpen] = useState(true)
    const [showButton, setShowButton] = useState(false)

    useEffect(() => {
      const toc = document.querySelector(".toc")
      if (toc) {
        toc.classList.toggle("collapsed", !open)
      }
      setShowButton(!open)
    }, [open])

    return (
      <button
        class={`toc-toggle-btn ${open ? "open" : "closed"} ${showButton ? "visible" : "hidden"}`}
        onClick={() => setOpen(!open)}
        title={open ? "Hide Table of Contents" : "Show Table of Contents"}
      >
        {open ? "❯" : "❮"}
      </button>
    )
  }

  return TocToggle
}) satisfies QuartzComponentConstructor
