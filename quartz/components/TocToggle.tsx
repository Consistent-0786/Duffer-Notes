import { QuartzComponent, QuartzComponentConstructor } from "./types"
import { useEffect } from "preact/hooks"
import "../components/styles/tocToggle.scss"

export default (() => {
  const TocToggle: QuartzComponent = () => {
    useEffect(() => {}, [])
    return null
  }
  return TocToggle
}) satisfies QuartzComponentConstructor
