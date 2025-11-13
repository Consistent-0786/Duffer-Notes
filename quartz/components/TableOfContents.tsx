import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import style from "./styles/toc.scss"
import { i18n } from "../i18n"
import { classNames } from "../util/lang"

let numTocs = 0

export default (() => {
  const TableOfContents: QuartzComponent = ({ fileData, displayClass, cfg }: QuartzComponentProps) => {
    if (!fileData.toc) {
      return null
    }

    const id = `toc-${numTocs++}`

    return (
      <div class={classNames(displayClass, "toc-container-outer")}>
        <button
          type="button"
          class="toc-toggle"
          aria-controls="toc-section"
          aria-expanded="false"
          onclick="document.querySelector('.toc-section')?.classList.toggle('collapsed')"
        >
          ☰
        </button>

        <section id="toc-section" class="toc-section collapsed">
          <h3 class="toc-title">{i18n(cfg.locale).components.tableOfContents.title}</h3>
          <ul class="toc-list" id={id}>
            {fileData.toc.map((tocEntry) => (
              <li key={tocEntry.slug} class={`depth-${tocEntry.depth}`}>
                <a href={`#${tocEntry.slug}`} data-for={tocEntry.slug}>
                  {tocEntry.text}
                </a>
              </li>
            ))}
          </ul>
        </section>
      </div>
    )
  }

  TableOfContents.css = style
  return TableOfContents
}) satisfies QuartzComponentConstructor
