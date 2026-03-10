(function () {
  const slides = Array.from(document.querySelectorAll(".hero-slide"));
  let slideIndex = 0;

  function setSlide(index) {
    slides.forEach((slide, idx) => {
      slide.classList.toggle("active", idx === index);
    });
  }

  if (slides.length > 1) {
    setSlide(0);
    setInterval(function () {
      slideIndex = (slideIndex + 1) % slides.length;
      setSlide(slideIndex);
    }, 5200);
  }

  function formatDate(value) {
    if (!value) return "Date unavailable";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Date unavailable";
    return date.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric"
    });
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  async function loadDynamicContent() {
    const newsLead = document.getElementById("newsLead");
    const newsList = document.getElementById("newsList");
    const eventsList = document.getElementById("eventsList");

    if (!newsLead || !newsList || !eventsList) return;

    try {
      const [newsPayload, eventPayload] = await Promise.all([
        window.apiFetch("/api/content/news?limit=4"),
        window.apiFetch("/api/content/events?limit=4")
      ]);

      const newsItems = Array.isArray(newsPayload.items) ? newsPayload.items : [];
      const eventItems = Array.isArray(eventPayload.items) ? eventPayload.items : [];

      if (newsItems.length > 0) {
        const lead = newsItems[0];
        const leadImage =
          lead.image_url ||
          "https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80";

        newsLead.innerHTML = `
          <img src="${escapeHtml(leadImage)}" loading="lazy" decoding="async" data-lazy="auto" alt="${escapeHtml(
          lead.title
        )}" />
          <div class="news-lead-copy">
            <p class="tag">${escapeHtml(formatDate(lead.published_at))}</p>
            <h3>${escapeHtml(lead.title)}</h3>
            <p>${escapeHtml(lead.summary || "")}</p>
            <a class="card-link" href="${escapeHtml(lead.link || "contact.html")}">Read Story <i class="fa-solid fa-arrow-right"></i></a>
          </div>
        `;

        const listItems = newsItems
          .slice(1, 4)
          .map(function (item) {
            const image =
              item.image_url ||
              "https://images.unsplash.com/photo-1523580846011-d3a5bc25702b?auto=format&fit=crop&w=300&q=80";

            return `
              <article class="news-item">
                <img src="${escapeHtml(image)}" loading="lazy" decoding="async" data-lazy="auto" alt="${escapeHtml(
              item.title
            )}" />
                <div>
                  <p class="tag">${escapeHtml(formatDate(item.published_at))}</p>
                  <h4>${escapeHtml(item.title)}</h4>
                </div>
              </article>
            `;
          })
          .join("");

        if (listItems) {
          newsList.innerHTML = listItems;
        }
      }

      if (eventItems.length > 0) {
        eventsList.innerHTML = eventItems
          .map(function (event, index) {
            const borderStyle =
              index < eventItems.length - 1
                ? ' style="padding: 0.55rem 0; border-bottom: 1px solid #e5edf9"'
                : ' style="padding: 0.55rem 0"';

            return `
              <li${borderStyle}>
                <strong>${escapeHtml(event.title)}</strong>
                <p class="section-note" style="font-size: 0.84rem">${escapeHtml(
                  `${formatDate(event.event_date)} • ${event.location || "Main Campus"}`
                )}</p>
              </li>
            `;
          })
          .join("");
      }
    } catch (_error) {
      // Keep static homepage content as graceful fallback.
    }
  }

  const modalMap = {
    register: document.getElementById("registerModal"),
    login: document.getElementById("loginModal"),
    reset: document.getElementById("resetModal")
  };

  function openModal(key) {
    const modal = modalMap[key];
    if (modal) {
      modal.classList.add("show");
      modal.setAttribute("aria-hidden", "false");
    }
  }

  function closeModal(key) {
    const modal = modalMap[key];
    if (modal) {
      modal.classList.remove("show");
      modal.setAttribute("aria-hidden", "true");
    }
  }

  document.querySelectorAll("[data-open-modal]").forEach(function (button) {
    button.addEventListener("click", function () {
      openModal(button.getAttribute("data-open-modal"));
    });
  });

  document.querySelectorAll("[data-close-modal]").forEach(function (button) {
    button.addEventListener("click", function () {
      closeModal(button.getAttribute("data-close-modal"));
    });
  });

  Object.values(modalMap).forEach(function (modal) {
    if (!modal) return;
    modal.addEventListener("click", function (event) {
      if (event.target === modal) {
        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");
      }
    });
  });

  // Registration
  const registrationForm = document.getElementById("registrationForm");
  const registerStatus = document.getElementById("registerStatus");
  const profileInput = document.getElementById("profilePicture");
  const preview = document.getElementById("profilePreview");

  function setRegisterStatus(message, ok) {
    if (!registerStatus) return;
    registerStatus.className = `status ${ok ? "ok" : "err"}`;
    registerStatus.textContent = message;
  }

  if (profileInput && preview) {
    profileInput.addEventListener("change", function () {
      const file = profileInput.files?.[0];
      if (!file) {
        preview.innerHTML = "No photo selected";
        return;
      }

      if (!file.type.startsWith("image/")) {
        profileInput.value = "";
        preview.innerHTML = "Only image files are allowed.";
        return;
      }

      if (file.size > 5 * 1024 * 1024) {
        profileInput.value = "";
        preview.innerHTML = "Maximum file size is 5MB.";
        return;
      }

      const reader = new FileReader();
      reader.onload = function (event) {
        preview.innerHTML = `<img src="${event.target.result}" alt="Preview" style="max-height:120px;border-radius:10px;">`;
      };
      reader.readAsDataURL(file);
    });
  }

  if (registrationForm) {
    registrationForm.addEventListener("submit", async function (event) {
      event.preventDefault();

      const password = registrationForm.querySelector("#password").value;
      const confirmPassword = registrationForm.querySelector("#confirmPassword").value;
      if (password !== confirmPassword) {
        setRegisterStatus("Passwords do not match.", false);
        return;
      }

      const formData = new FormData(registrationForm);
      const selectedCourses = Array.from(registrationForm.querySelectorAll('input[name="courses"]:checked')).map(
        function (item) {
          return item.value;
        }
      );

      formData.delete("courses");
      selectedCourses.forEach(function (course) {
        formData.append("courses", course);
      });

      const submitButton = registrationForm.querySelector('button[type="submit"]');
      const originalText = submitButton.textContent;
      submitButton.disabled = true;
      submitButton.textContent = "Submitting...";

      try {
        const payload = await fetch(`${window.API_BASE_URL}/api/register`, {
          method: "POST",
          body: formData
        }).then(async function (response) {
          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || "Registration failed");
          }
          return data;
        });

        setRegisterStatus(payload.message || "Registration successful.", true);
        registrationForm.reset();
        if (preview) {
          preview.innerHTML = "No photo selected";
        }

        setTimeout(function () {
          closeModal("register");
          openModal("login");
        }, 1100);
      } catch (error) {
        setRegisterStatus(error.message, false);
      } finally {
        submitButton.disabled = false;
        submitButton.textContent = originalText;
      }
    });
  }

  // Login
  const loginForm = document.getElementById("loginForm");
  const loginStatus = document.getElementById("loginStatus");
  let currentRole = "student";

  function setLoginStatus(message, ok) {
    if (!loginStatus) return;
    loginStatus.className = `status ${ok ? "ok" : "err"}`;
    loginStatus.textContent = message;
  }

  function roleEndpoint(role) {
    if (role === "admin") return "/api/admins/login";
    if (role === "teacher") return "/api/teachers/login";
    return "/api/students/login";
  }

  function roleDataKey(role) {
    if (role === "admin") return "admin";
    if (role === "teacher") return "teacher";
    return "student";
  }

  function roleStorage(role) {
    if (role === "admin") {
      return {
        token: "adminToken",
        data: "adminData",
        auth: "adminLoggedIn",
        redirect: "admin-dashboard.html"
      };
    }

    if (role === "teacher") {
      return {
        token: "teacherToken",
        data: "teacherData",
        auth: "teacherLoggedIn",
        redirect: "teacher-dashboard.html"
      };
    }

    return {
      token: "studentToken",
      data: "studentData",
      auth: "studentLoggedIn",
      redirect: "student-profile.html"
    };
  }

  document.querySelectorAll(".role-btn").forEach(function (button) {
    button.addEventListener("click", function () {
      currentRole = button.getAttribute("data-role");
      document.querySelectorAll(".role-btn").forEach(function (node) {
        node.classList.remove("active");
      });
      button.classList.add("active");
      const roleLabel = currentRole.charAt(0).toUpperCase() + currentRole.slice(1);
      const modalTitle = document.getElementById("loginTitle");
      if (modalTitle) {
        modalTitle.textContent = `${roleLabel} Portal Login`;
      }
      setLoginStatus("", true);
    });
  });

  if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const email = loginForm.querySelector("#loginEmail").value.trim();
      const password = loginForm.querySelector("#loginPassword").value;
      const button = loginForm.querySelector('button[type="submit"]');
      const originalText = button.textContent;

      button.disabled = true;
      button.textContent = "Signing in...";

      try {
        const payload = await window.apiFetch(roleEndpoint(currentRole), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });

        const key = roleDataKey(currentRole);
        const storage = roleStorage(currentRole);
        localStorage.setItem(storage.token, payload.token || "");
        localStorage.setItem(storage.auth, "true");
        localStorage.setItem(storage.data, JSON.stringify(payload[key] || {}));

        setLoginStatus("Login successful. Redirecting...", true);

        setTimeout(function () {
          window.location.href = storage.redirect;
        }, 700);
      } catch (error) {
        setLoginStatus(error.message, false);
      } finally {
        button.disabled = false;
        button.textContent = originalText;
      }
    });
  }

  // Password reset
  const requestResetForm = document.getElementById("requestResetForm");
  const confirmResetForm = document.getElementById("confirmResetForm");
  const resetStatus = document.getElementById("resetStatus");
  const resendButton = document.getElementById("resendReset");

  function setResetStatus(message, ok) {
    if (!resetStatus) return;
    resetStatus.className = `status ${ok ? "ok" : "err"}`;
    resetStatus.textContent = message;
  }

  if (requestResetForm) {
    requestResetForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const email = requestResetForm.querySelector("#resetEmail").value.trim();
      const role = requestResetForm.querySelector("#resetRole").value;

      try {
        const payload = await window.apiFetch("/api/auth/forgot-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, role })
        });

        setResetStatus(payload.message || "Reset code sent.", true);
      } catch (error) {
        setResetStatus(error.message, false);
      }
    });
  }

  if (confirmResetForm) {
    confirmResetForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const email = confirmResetForm.querySelector("#resetEmailConfirm").value.trim();
      const resetCode = confirmResetForm.querySelector("#resetCode").value.trim();
      const newPassword = confirmResetForm.querySelector("#newPassword").value;
      const confirmPassword = confirmResetForm.querySelector("#confirmNewPassword").value;
      const role = confirmResetForm.querySelector("#confirmResetRole").value;

      if (newPassword !== confirmPassword) {
        setResetStatus("Passwords do not match.", false);
        return;
      }

      try {
        const payload = await window.apiFetch("/api/auth/reset-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, resetCode, newPassword, confirmPassword, role })
        });

        setResetStatus(payload.message || "Password reset complete.", true);
      } catch (error) {
        setResetStatus(error.message, false);
      }
    });
  }

  if (resendButton) {
    resendButton.addEventListener("click", async function () {
      const email = document.getElementById("resetEmail").value.trim();
      const role = document.getElementById("resetRole").value;

      if (!email) {
        setResetStatus("Enter your email first.", false);
        return;
      }

      try {
        const payload = await window.apiFetch("/api/auth/resend-reset-code", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, role })
        });

        setResetStatus(payload.message || "Reset code resent.", true);
      } catch (error) {
        setResetStatus(error.message, false);
      }
    });
  }

  document.querySelectorAll("[data-reset-open]").forEach(function (node) {
    node.addEventListener("click", function () {
      closeModal("login");
      openModal("reset");
    });
  });

  document.querySelectorAll("[data-open-login]").forEach(function (node) {
    node.addEventListener("click", function () {
      closeModal("register");
      openModal("login");
    });
  });

  loadDynamicContent();
})();
