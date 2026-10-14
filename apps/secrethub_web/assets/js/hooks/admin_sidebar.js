const storageKey = "secrethub:admin-sidebar-collapsed"

const AdminSidebar = {
  mounted() {
    this.collapsed = this.el.dataset.collapsed === "true"
    this.groupStates = new Map()

    try {
      const saved = window.localStorage.getItem(storageKey)
      if (saved !== null) this.collapsed = saved === "true"
    } catch (_error) {
      // The toggle still works when browser storage is unavailable.
    }

    this.handleClick = (event) => {
      if (!event.target.closest("[data-sidebar-toggle]")) return

      this.collapsed = !this.collapsed
      this.applyState()

      try {
        window.localStorage.setItem(storageKey, String(this.collapsed))
      } catch (_error) {
        // Keep the current page usable without a persisted preference.
      }
    }

    this.el.addEventListener("click", this.handleClick)
    this.applyState()
  },

  updated() {
    this.applyState()
  },

  destroyed() {
    this.el.removeEventListener("click", this.handleClick)
  },

  applyState() {
    this.el.dataset.collapsed = String(this.collapsed)

    const toggle = this.el.querySelector("[data-sidebar-toggle]")
    toggle.setAttribute("aria-expanded", String(!this.collapsed))
    toggle.setAttribute("aria-label", this.collapsed ? "Expand sidebar" : "Collapse sidebar")

    this.el.querySelectorAll("a").forEach((link) => {
      const label = link.querySelector(".admin-sidebar-label")?.textContent.trim()
      if (!label) return

      link.setAttribute("aria-label", label)
      link.setAttribute("title", label)
    })

    this.el.querySelectorAll("#admin-sidebar-menu details").forEach((group, index) => {
      if (this.collapsed) {
        if (!this.groupStates.has(index)) this.groupStates.set(index, group.open)
        group.open = true
      } else if (this.groupStates.has(index)) {
        group.open = this.groupStates.get(index)
      }
    })

    if (!this.collapsed) this.groupStates.clear()
  },
}

export default AdminSidebar
