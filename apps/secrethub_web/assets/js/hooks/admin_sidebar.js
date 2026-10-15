const storageKey = "secrethub:admin-sidebar-collapsed"

export const AdminSidebarNavigation = {
  mounted() {
    this.syncActiveNav()
  },

  updated() {
    this.syncActiveNav()
  },

  reconnected() {
    this.activeNav = null
    this.syncActiveNav()
  },

  syncActiveNav() {
    const activeNav = this.el.dataset.activeNav
    if (this.activeNav === activeNav) return

    this.activeNav = activeNav
    this.pushEventTo("#admin-sidebar", "set_active_nav", {active_nav: activeNav})
      .then(results => {
        if (results.some(result => result.status === "rejected")) this.activeNav = null
      })
      .catch(() => { this.activeNav = null })
  },
}

const AdminSidebar = {
  mounted() {
    this.collapsed = this.el.dataset.collapsed === "true"
    this.groupStates = new Map()
    this.navigationScrollTop = null

    this.handleNavigationStart = ({detail}) => {
      if (!["redirect", "patch", "initial"].includes(detail.kind)) return
      if (this.navigationScrollTop !== null) return
      this.navigationScrollTop = this.el.querySelector(".admin-sidebar-scroll").scrollTop
    }

    this.handleNavigationStop = ({detail}) => {
      if (!["redirect", "patch", "initial"].includes(detail.kind)) return
      if (this.navigationScrollTop === null) return

      this.el.querySelector(".admin-sidebar-scroll").scrollTo({
        top: this.navigationScrollTop, behavior: "instant",
      })
      // A redirect finishes before the new root's initial join patches the DOM.
      if (detail.kind !== "redirect") this.navigationScrollTop = null
    }

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
    window.addEventListener("phx:page-loading-start", this.handleNavigationStart)
    window.addEventListener("phx:page-loading-stop", this.handleNavigationStop)
    this.applyState()
  },

  beforeUpdate() {
    this.scrollTop = this.navigationScrollTop ?? this.el.querySelector(".admin-sidebar-scroll").scrollTop

    if (!this.collapsed) {
      this.el.querySelectorAll("#admin-sidebar-menu details").forEach((group, index) => {
        this.groupStates.set(index, group.open)
      })
    }
  },

  updated() {
    this.applyState()
    this.el.querySelector(".admin-sidebar-scroll").scrollTo({top: this.scrollTop, behavior: "instant"})
  },

  destroyed() {
    this.el.removeEventListener("click", this.handleClick)
    window.removeEventListener("phx:page-loading-start", this.handleNavigationStart)
    window.removeEventListener("phx:page-loading-stop", this.handleNavigationStop)
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

      const tooltipId = link.dataset.sidebarMenuTooltip
      if (!tooltipId) {
        link.setAttribute("title", label)
        return
      }

      if (this.collapsed) {
        link.setAttribute("interestfor", tooltipId)
        link.setAttribute("aria-describedby", tooltipId)
        link.setAttribute("style", link.dataset.sidebarMenuAnchor)
        link.setAttribute("title", label)
      } else {
        link.removeAttribute("interestfor")
        link.removeAttribute("aria-describedby")
        link.removeAttribute("title")
        link.style.removeProperty("anchor-name")

        const tooltip = document.getElementById(tooltipId)
        if (tooltip?.hidePopover && tooltip.matches(":popover-open")) tooltip.hidePopover()
      }
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
