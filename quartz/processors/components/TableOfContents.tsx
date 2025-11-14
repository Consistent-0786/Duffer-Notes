import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import style from "./styles/toc.scss"
import { i18n } from "../i18n"
import { classNames } from "../util/lang"
// @ts-ignore
import script from "./scripts/toc.inline"

export default (() => {
  const TableOfContents: QuartzComponent = ({ fileData, displayClass, cfg }: QuartzComponentProps) => {
    if (!fileData?.toc) return null

    return (
      <aside class={classNames(displayClass, "quartz-toc-sidebar")}>
        <nav class="toc-section" aria-label="Table of Contents">
          <h3 class="toc-title">{i18n(cfg.locale).components.tableOfContents.title}</h3>
          <ul class="toc-list">
            {fileData.toc.map((tocEntry) => (
              <li key={tocEntry.slug} class={`depth-${tocEntry.depth}`}>
                <a href={`#${tocEntry.slug}`} data-for={tocEntry.slug}>
                  {tocEntry.text}
                </a>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
    )
  }

  TableOfContents.css = style
  TableOfContents.afterDOMLoaded = script
  return TableOfContents
}) satisfies QuartzComponentConstructor
