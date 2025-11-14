import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import script from "./scripts/graph.inline"
import style from "./styles/graph.scss"
import { i18n } from "../i18n"
import { classNames } from "../util/lang"

export default (() => {
  const Graph: QuartzComponent = ({ displayClass, cfg, fileData }: QuartzComponentProps) => {
    const isHome = fileData?.slug === "index" || fileData?.fileData?.slug === "index"
    return (
      <div class={classNames(displayClass, "graph-wrapper")}>
        {!isHome && (<button id="toggle-graph" class="graph-toggle">Toggle Graph</button>)}
        <section id="graph-section" class={isHome ? "graph" : "graph collapsed"}>
          <h3>{i18n(cfg.locale).components.graph.title}</h3>
          <div class="graph-container"></div>
        </section>
      </div>
    )
  }

  Graph.css = style
  Graph.afterDOMLoaded = script
  return Graph
}) satisfies QuartzComponentConstructor
