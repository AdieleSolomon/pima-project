(function () {
  const menuToggle = document.getElementById("menuToggle");
  const mainNav = document.getElementById("mainNav");

  const menuTree = [
    { label: "Home", href: "index.html" },
    {
      label: "About Us",
      children: [
        { label: "Our Story", href: "about.html#story" },
        { label: "Mission & Vision", href: "about.html#mission" },
        { label: "Leadership", href: "about.html#leadership" },
        { label: "Institution Profile", href: "about.html" }
      ]
    },
    {
      label: "Academics",
      children: [
        {
          label: "Programs",
          children: [
            { label: "Construction Trades", href: "programs.html#core-programs" },
            { label: "Electrical & Energy", href: "programs.html#core-programs" },
            { label: "Mechanical & Auto", href: "programs.html#core-programs" },
            { label: "Digital Repairs", href: "programs.html#short-courses" }
          ]
        },
        { label: "All Programs", href: "programs.html" },
        { label: "Short Courses", href: "programs.html#short-courses" },
        { label: "Admission Track", href: "programs.html#admission-track" }
      ]
    },
    {
      label: "Administration",
      children: [
        { label: "The Registry", href: "about.html#leadership" },
        { label: "Student Affairs", href: "student-profile.html" },
        {
          label: "Units",
          children: [
            { label: "Admissions Office", href: "contact.html" },
            { label: "Support Desk", href: "contact.html" },
            { label: "Quality Assurance", href: "about.html#mission" }
          ]
        }
      ]
    },
    {
      label: "Admission",
      children: [
        { label: "Apply Now", href: "index.html" },
        { label: "Eligibility Guide", href: "programs.html#admission-track" },
        { label: "Tuition Enquiry", href: "contact.html" }
      ]
    },
    {
      label: "Research & Media",
      children: [
        { label: "News & Updates", href: "index.html#news-updates" },
        { label: "Upcoming Events", href: "index.html#events-updates" },
        { label: "Photo Highlights", href: "index.html#photo-highlights" }
      ]
    },
    {
      label: "Portals",
      children: [
        { label: "Student Portal", href: "student-profile.html" },
        { label: "Teacher Portal", href: "teacher-dashboard.html" },
        { label: "Admin Portal", href: "admin-dashboard.html" }
      ]
    },
    { label: "Contact", href: "contact.html" },
    { label: "Apply", href: "index.html", cta: true }
  ];

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function renderMenuLevel(items, level, pathPrefix) {
    const listClass = level === 0 ? "menu" : `submenu submenu-level-${level}`;
    const roleAttr = level === 0 ? 'role="menubar"' : 'role="menu"';

    const inner = items
      .map(function (item, index) {
        const itemPath = `${pathPrefix}-${index}`;
        if (item.children && item.children.length) {
          const controlsId = `submenu-${itemPath}`;
          const iconClass = level === 0 ? "fa-chevron-down" : "fa-chevron-right";
          return `
            <li class="has-submenu" role="none">
              <button type="button" class="menu-trigger" aria-expanded="false" aria-controls="${controlsId}" role="menuitem">
                ${escapeHtml(item.label)}
                <i class="fa-solid ${iconClass}"></i>
              </button>
              <ul id="${controlsId}" class="submenu submenu-level-${level + 1}" role="menu">
                ${renderMenuLevel(item.children, level + 1, itemPath)}
              </ul>
            </li>
          `;
        }

        const ctaClass = level === 0 && item.cta ? "menu-cta" : "";
        return `
          <li role="none" class="${ctaClass}">
            <a href="${escapeHtml(item.href)}" role="menuitem">${escapeHtml(item.label)}</a>
          </li>
        `;
      })
      .join("");

    return level === 0 ? `<ul class="${listClass}" ${roleAttr}>${inner}</ul>` : inner;
  }

  function hydrateMegaMenu() {
    if (!mainNav || mainNav.getAttribute("data-menu") !== "mega") {
      return;
    }

    mainNav.innerHTML = renderMenuLevel(menuTree, 0, "root");
  }

  function markActiveLink() {
    if (!mainNav) return;

    const currentPath = window.location.pathname.split("/").pop() || "index.html";

    mainNav.querySelectorAll("a[href]").forEach(function (link) {
      const href = link.getAttribute("href");
      if (!href || href.startsWith("#") || href.startsWith("mailto:")) {
        return;
      }

      const normalized = href.split("#")[0];
      if (normalized === currentPath) {
        link.classList.add("active");
        link.setAttribute("aria-current", "page");
      }
    });
  }

  function closeAllDesktopSubmenus() {
    if (!mainNav) return;
    mainNav.querySelectorAll(".has-submenu").forEach(function (node) {
      node.classList.remove("open-desktop");
      node.classList.remove("open");
      const trigger = node.querySelector(":scope > .menu-trigger");
      if (trigger) {
        trigger.setAttribute("aria-expanded", "false");
      }
    });
  }

  function setupDesktopKeyboardNavigation() {
    if (!mainNav) return;

    mainNav.querySelectorAll(".has-submenu > .menu-trigger").forEach(function (button) {
      button.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          if (window.innerWidth <= 1100) {
            return;
          }

          const parent = button.parentElement;
          const isOpen = parent.classList.contains("open-desktop");
          closeAllDesktopSubmenus();
          if (!isOpen) {
            parent.classList.add("open-desktop");
            button.setAttribute("aria-expanded", "true");
          }
        }

        if (event.key === "Escape") {
          closeAllDesktopSubmenus();
        }
      });
    });
  }

  function setupMobileDropdowns() {
    if (!mainNav) return;

    mainNav.querySelectorAll(".has-submenu > .menu-trigger").forEach(function (button) {
      button.addEventListener("click", function () {
        if (window.innerWidth > 1100) {
          const parent = button.parentElement;
          const isOpen = parent.classList.contains("open-desktop");
          closeAllDesktopSubmenus();
          if (!isOpen) {
            parent.classList.add("open-desktop");
            button.setAttribute("aria-expanded", "true");
          }
          return;
        }

        const parent = button.parentElement;
        const isOpen = parent.classList.contains("open");
        parent.classList.toggle("open");
        button.setAttribute("aria-expanded", String(!isOpen));
      });
    });
  }

  function setupMainNavToggle() {
    if (!menuToggle || !mainNav) {
      return;
    }

    menuToggle.addEventListener("click", function () {
      const expanded = menuToggle.getAttribute("aria-expanded") === "true";
      menuToggle.setAttribute("aria-expanded", String(!expanded));
      mainNav.classList.toggle("open");
    });

    mainNav.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        if (window.innerWidth <= 1100) {
          mainNav.classList.remove("open");
          menuToggle.setAttribute("aria-expanded", "false");
          closeAllDesktopSubmenus();
        }
      });
    });

    document.addEventListener("click", function (event) {
      const clickedInside = mainNav.contains(event.target) || menuToggle.contains(event.target);

      if (window.innerWidth <= 1100 && !clickedInside) {
        mainNav.classList.remove("open");
        menuToggle.setAttribute("aria-expanded", "false");
      }

      if (window.innerWidth > 1100 && !clickedInside) {
        closeAllDesktopSubmenus();
      }
    });

    document.addEventListener("keydown", function (event) {
      if (event.key !== "Escape") return;

      if (window.innerWidth <= 1100) {
        mainNav.classList.remove("open");
        menuToggle.setAttribute("aria-expanded", "false");
      }

      closeAllDesktopSubmenus();
    });
  }

  function attachFocusHelpers() {
    document.querySelectorAll("[data-year]").forEach(function (node) {
      node.textContent = new Date().getFullYear();
    });

    document.querySelectorAll("main img:not([loading])").forEach(function (image) {
      image.setAttribute("loading", "lazy");
      image.setAttribute("decoding", "async");
    });

    document.querySelectorAll("img[data-lazy='auto']").forEach(function (image) {
      if (!image.hasAttribute("loading")) image.setAttribute("loading", "lazy");
      if (!image.hasAttribute("decoding")) image.setAttribute("decoding", "async");
    });
  }

  hydrateMegaMenu();
  markActiveLink();
  setupMainNavToggle();
  setupDesktopKeyboardNavigation();
  setupMobileDropdowns();
  attachFocusHelpers();
})();
