// If you want to use Phoenix channels, run `mix help phx.gen.channel`
// to get started and then uncomment the line below.
// import "./user_socket.js"

// You can include dependencies in two ways.
//
// The simplest option is to put them in assets/vendor and
// import them using relative paths:
//
//     import "../vendor/some-package.js"
//
// Alternatively, you can `npm install some-package --prefix assets` and import
// them using a path starting with the package name:
//
//     import "some-package"
//
// If you have dependencies that try to import CSS, bun will generate a separate `app.css` file.
// To load it, simply add a second `<link>` to your `root.html.heex` file.

// Include phoenix_html to handle method=PUT/DELETE in forms and buttons.
import "phoenix_html"
// Establish Phoenix Socket and LiveView configuration.
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import topbar from "../vendor/topbar"

// DuskMoon UI hooks and element registration
import * as DuskmoonHooks from "phoenix_duskmoon/hooks"
import "@duskmoon-dev/elements/register"

const writeClipboard = async (text) => {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }

  const textarea = document.createElement("textarea")
  textarea.value = text
  textarea.setAttribute("readonly", "")
  textarea.style.position = "fixed"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()

  try {
    if (!document.execCommand("copy")) {
      throw new Error("copy command failed")
    }
  } finally {
    document.body.removeChild(textarea)
  }
}

const Hooks = {
  ...DuskmoonHooks,
  PreserveFormValues: {
    mounted() {
      this.captureValues = () => {
        this.values = new Map()

        this.el.querySelectorAll("input[name], textarea[name], select[name]").forEach((field) => {
          if (field.type === "hidden" || field.type === "file") return

          this.values.set(this.fieldKey(field), this.readField(field))
        })
      }

      this.captureValues()
      this.el.addEventListener("input", this.captureValues, true)
      this.el.addEventListener("change", this.captureValues, true)
    },
    beforeUpdate() {
      this.captureValues()
    },
    updated() {
      this.el.querySelectorAll("input[name], textarea[name], select[name]").forEach((field) => {
        if (field.type === "hidden" || field.type === "file") return

        const key = this.fieldKey(field)
        if (!this.values?.has(key)) return

        this.writeField(field, this.values.get(key))
      })
    },
    destroyed() {
      this.el.removeEventListener("input", this.captureValues, true)
      this.el.removeEventListener("change", this.captureValues, true)
    },
    readField(field) {
      if (field.type === "checkbox" || field.type === "radio") {
        return {checked: field.checked}
      }

      if (field.multiple) {
        return {
          selected: Array.from(field.selectedOptions).map((option) => option.value),
        }
      }

      return {value: field.value}
    },
    fieldKey(field) {
      if (field.type === "checkbox" || field.type === "radio") {
        return `${field.name}:${field.value}`
      }

      return field.name
    },
    writeField(field, state) {
      if (field.type === "checkbox" || field.type === "radio") {
        field.checked = state.checked
        return
      }

      if (field.multiple) {
        Array.from(field.options).forEach((option) => {
          option.selected = state.selected.includes(option.value)
        })
        return
      }

      field.value = state.value
    }
  },
  CopyToClipboard: {
    mounted() {
      this.handleClick = async (event) => {
        event.preventDefault()

        const value = this.el.dataset.copyValue || ""
        if (!value) return

        try {
          await writeClipboard(value)
          this.markCopied()
        } catch (_error) {
          this.markFailed()
        }
      }

      this.el.addEventListener("click", this.handleClick)
    },
    destroyed() {
      this.el.removeEventListener("click", this.handleClick)
    },
    markCopied() {
      this.setTemporaryState("Copied", ["text-success", "border-success"])
    },
    markFailed() {
      this.setTemporaryState("Copy failed", ["text-error", "border-error"])
    },
    setTemporaryState(label, classes) {
      clearTimeout(this.resetTimer)

      if (!this.originalLabel) {
        this.originalLabel = this.el.getAttribute("aria-label")
      }

      this.el.setAttribute("aria-label", label)
      this.el.setAttribute("title", label)
      this.el.classList.add(...classes)

      this.resetTimer = setTimeout(() => {
        this.el.setAttribute("aria-label", this.originalLabel)
        this.el.setAttribute("title", this.originalLabel)
        this.el.classList.remove("text-success", "border-success", "text-error", "border-error")
      }, 1400)
    }
  }
}

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  params: {_csrf_token: csrfToken},
  hooks: Hooks,
})

// Show progress bar on live navigation and form submits
const themeColor = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()
topbar.config({barColors: {0: themeColor("--color-primary")}, shadowBlur: 0})
window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
window.addEventListener("phx:page-loading-stop", _info => topbar.hide())

// Handle file download events from LiveView
window.addEventListener("phx:download", (event) => {
  const {filename, content} = event.detail
  const blob = new Blob([content], {type: "text/plain"})
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
})

// connect if there are any LiveViews on the page
liveSocket.connect()

// expose liveSocket on window for web console debug logs and latency simulation:
// >> liveSocket.enableDebug()
// >> liveSocket.enableLatencySim(1000)  // enabled for duration of browser session
// >> liveSocket.disableLatencySim()
window.liveSocket = liveSocket

// The lines below enable quality of life phoenix_live_reload
// development features:
//
//     1. stream server logs to the browser console
//     2. click on elements to jump to their definitions in your code editor
//
if (process.env.NODE_ENV === "development") {
  window.addEventListener("phx:live_reload:attached", ({detail: reloader}) => {
    // Enable server log streaming to client.
    // Disable with reloader.disableServerLogs()
    reloader.enableServerLogs()

    // Open configured PLUG_EDITOR at file:line of the clicked element's HEEx component
    //
    //   * click with "c" key pressed to open at caller location
    //   * click with "d" key pressed to open at function component definition location
    let keyDown
    window.addEventListener("keydown", e => keyDown = e.key)
    window.addEventListener("keyup", e => keyDown = null)
    window.addEventListener("click", e => {
      if(keyDown === "c"){
        e.preventDefault()
        e.stopImmediatePropagation()
        reloader.openEditorAtCaller(e.target)
      } else if(keyDown === "d"){
        e.preventDefault()
        e.stopImmediatePropagation()
        reloader.openEditorAtDef(e.target)
      }
    }, true)

    window.liveReloader = reloader
  })
}
