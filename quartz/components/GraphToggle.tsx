import { QuartzComponent, QuartzComponentConstructor } from "./types"
import { useEffect, useState } from "preact/hooks"
import "../components/styles/graphToggle.scss"

export default (() => {
  const GraphToggle: QuartzComponent = () => {
    const [open, setOpen] = useState(false)
    useEffect(() => {
      const btns = document.querySelectorAll(".graph-toggle")
      btns.forEach((b) => (b as HTMLElement).style.display = open ? "block" : "block")
    }, [open])

    return null
  }
  return GraphToggle
}) satisfies QuartzComponentConstructor
