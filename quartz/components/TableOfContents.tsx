import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import script from "./scripts/toc.inline"
import style from "./styles/toc.scss"
import { i18n } from "../i18n"
import { classNames } from "../util/lang"

export default (() => {
  const TableOfContents: QuartzComponent = ({ fileData, displayClass, cfg }: QuartzComponentProps) => {
    if (!fileData.toc) return null
    return (
      <div class={classNames(displayClass, "toc-wrapper")}>
        <button id="toggle-toc" class="toc-toggle">Toggle TOC</button>
        <section id="toc-section" class="toc collapsed">
          <h3>{i18n(cfg.locale).components.tableOfContents.title}</h3>
          <ul>
            {fileData.toc.map((entry) => (
              <li key={entry.slug}>
                <a href={`#${entry.slug}`} data-for={entry.slug}>{entry.text}</a>
              </li>
            ))}
          </ul>
        </section>
      </div>
    )
  }

  TableOfContents.css = style
  TableOfContents.afterDOMLoaded = script
  return TableOfContents
}) satisfies QuartzComponentConstructor
