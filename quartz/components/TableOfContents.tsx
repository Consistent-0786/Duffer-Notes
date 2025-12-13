import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import style from "./styles/toc.scss"
import { i18n } from "../i18n"
import { classNames } from "../util/lang"
// @ts-ignore
import script from "./scripts/toc.inline"

/* Recursive TOC list renderer */
function TocList({ items }: { items: any[] }) {
  if (!items || items.length === 0) return null

  return (
    <ul class="toc-list">
      {items.map((item) => (
        <li key={item.slug} class={`depth-${item.depth - 1}`}>
          <a href={`#${item.slug}`} data-for={item.slug}>
            {item.text}
          </a>

          {item.children && item.children.length > 0 && (
            <TocList items={item.children} />
          )}
        </li>
      ))}
    </ul>
  )
}

export default (() => {
  const TableOfContents: QuartzComponent = ({ fileData, displayClass, cfg }: QuartzComponentProps) => {
    if (!fileData?.toc || fileData.toc.length === 0) return null

    return (
      <aside class={classNames(displayClass, "quartz-toc-sidebar")}>
        <nav class="toc-section" aria-label="Table of Contents">
          <h3 class="toc-title">
            {i18n(cfg.locale).components.tableOfContents.title}
          </h3>

          {/* Render nested TOC */}
          <TocList items={fileData.toc} />
        </nav>
      </aside>
    )
  }

  TableOfContents.css = style
  TableOfContents.afterDOMLoaded = script
  return TableOfContents
}) satisfies QuartzComponentConstructor
