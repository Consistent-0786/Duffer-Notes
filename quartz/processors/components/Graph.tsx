import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import script from "./scripts/graph.inline"
import style from "./styles/graph.scss"
import { i18n } from "../i18n"
import { classNames } from "../util/lang"

export default (() => {
  const Graph: QuartzComponent = ({ displayClass, cfg, fileData }: QuartzComponentProps) => {
    // show only on home (index)
    const slug = fileData?.slug ?? fileData?.fileData?.slug
    const isHome = slug === "index" || slug === "" || slug === "/"
    if (!isHome) return null

    return (
      <aside class={classNames(displayClass, "quartz-graph-embed")}>
        <section class="graph-section">
          <h3 class="graph-title">{i18n(cfg.locale).components.graph.title}</h3>
          <div class="graph-container" data-cfg={JSON.stringify({})}></div>
        </section>
      </aside>
    )
  }

  Graph.css = style
  Graph.afterDOMLoaded = script
  return Graph
}) satisfies QuartzComponentConstructor
