(function () {
  const loginSection = document.getElementById("loginSection");
  const dashboard = document.getElementById("dashboard");
  const loginMessage = document.getElementById("loginMessage");
  const tableBody = document.getElementById("studentsTableBody");
  const pageInfo = document.getElementById("pageInfo");
  const prevBtn = document.getElementById("prevBtn");
  const nextBtn = document.getElementById("nextBtn");
  const searchInput = document.getElementById("searchInput");
  const sortField = document.getElementById("sortField");
  const sortOrder = document.getElementById("sortOrder");

  let currentPage = 1;
  let totalPages = 1;
  const limit = 10;

  function setLoginMessage(text, kind) {
    if (!loginMessage) return;
    loginMessage.textContent = text;
    loginMessage.className = `login-message ${kind || ""}`;
  }

  function getToken() {
    return localStorage.getItem("teacherToken");
  }

  function getProfilePictureURL(url) {
    if (!url) return "https://ui-avatars.com/api/?name=Student&background=0a2f63&color=fff&size=120";
    if (url.startsWith("http")) return url;
    if (url.startsWith("/uploads/")) return `${window.API_BASE_URL}${url}`;
    return `${window.API_BASE_URL}/uploads/${url}`;
  }

  function safeCourses(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;

    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch (_error) {
      return String(value)
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
    }
  }

  function logout() {
    localStorage.removeItem("teacherToken");
    localStorage.removeItem("teacherData");
    localStorage.removeItem("teacherLoggedIn");

    dashboard?.classList.add("hidden");
    loginSection?.classList.remove("hidden");

    document.getElementById("loginForm")?.reset();
    setLoginMessage("You have been logged out.", "success");
  }

  window.logout = logout;

  function updateKpis(students) {
    const totalStudents = document.getElementById("totalStudents");
    const totalCourses = document.getElementById("totalCourses");
    const activeStudents = document.getElementById("activeStudents");

    const uniqueCourses = new Set();
    students.forEach((student) => {
      safeCourses(student.courses).forEach((course) => uniqueCourses.add(course));
    });

    if (totalStudents) totalStudents.textContent = String(students.length);
    if (totalCourses) totalCourses.textContent = String(uniqueCourses.size);
    if (activeStudents) activeStudents.textContent = String(students.length);
  }

  function renderRows(students) {
    if (!tableBody) return;

    tableBody.innerHTML = "";
    if (!students.length) {
      tableBody.innerHTML = '<tr><td colspan="7">No students found for your current filters.</td></tr>';
      return;
    }

    students.forEach((student) => {
      const row = document.createElement("tr");
      const courses = safeCourses(student.courses);
      const registered = student.created_at ? new Date(student.created_at).toLocaleDateString() : "-";

      row.innerHTML = `
        <td>${student.id}</td>
        <td>
          <span class="inline">
            <img src="${getProfilePictureURL(student.profilePictureUrl)}" alt="avatar" class="avatar"/>
            <span>${student.firstName || ""} ${student.lastName || ""}</span>
          </span>
        </td>
        <td>${student.email || "-"}</td>
        <td>${student.phone || "-"}</td>
        <td><span class="badge muted">${courses.length} course(s)</span></td>
        <td>${registered}</td>
        <td>
          <button class="btn-mini" data-view-id="${student.id}">View</button>
        </td>
      `;

      tableBody.appendChild(row);
    });

    tableBody.querySelectorAll("[data-view-id]").forEach((button) => {
      button.addEventListener("click", function () {
        openStudentDetails(button.getAttribute("data-view-id"));
      });
    });
  }

  function renderRecent(students) {
    const list = document.getElementById("recentRegistrations");
    if (!list) return;

    list.innerHTML = "";
    students.slice(0, 6).forEach((student) => {
      const li = document.createElement("li");
      li.textContent = `${student.firstName || ""} ${student.lastName || ""} joined ${
        student.created_at ? new Date(student.created_at).toLocaleDateString() : "recently"
      }`;
      list.appendChild(li);
    });
  }

  async function fetchStudents() {
    const token = getToken();
    if (!token) {
      logout();
      return;
    }

    const search = encodeURIComponent(searchInput?.value.trim() || "");
    const sort = encodeURIComponent(sortField?.value || "id");
    const order = encodeURIComponent(sortOrder?.value || "DESC");

    try {
      const payload = await window.apiFetch(
        `/api/students?page=${currentPage}&limit=${limit}&search=${search}&sort=${sort}&order=${order}`,
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      const students = payload.students || [];
      totalPages = payload.totalPages || 1;

      renderRows(students);
      renderRecent(students);
      updateKpis(students);

      if (pageInfo) {
        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
      }
      if (prevBtn) prevBtn.disabled = currentPage <= 1;
      if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
    } catch (error) {
      if (tableBody) {
        tableBody.innerHTML = `<tr><td colspan="7">${error.message}</td></tr>`;
      }
      if (String(error.message).toLowerCase().includes("session")) {
        logout();
      }
    }
  }

  async function openStudentDetails(id) {
    const token = getToken();
    if (!token) {
      logout();
      return;
    }

    try {
      const payload = await window.apiFetch(`/api/students/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      const student = payload.student;
      const courses = safeCourses(student.courses);

      const body = document.getElementById("studentDetailsBody");
      if (body) {
        body.innerHTML = `
          <div class="profile-grid">
            <aside class="profile-aside">
              <img class="profile-pic" src="${getProfilePictureURL(student.profilePictureUrl)}" alt="profile">
              <h3>${student.firstName || ""} ${student.lastName || ""}</h3>
              <p>${student.email || ""}</p>
            </aside>
            <div class="profile-main">
              <div class="info-list">
                <div class="info-item"><small>ID</small><strong>${student.id || "-"}</strong></div>
                <div class="info-item"><small>Phone</small><strong>${student.phone || "-"}</strong></div>
                <div class="info-item"><small>Age</small><strong>${student.age || "-"}</strong></div>
                <div class="info-item"><small>Education</small><strong>${student.education || "-"}</strong></div>
                <div class="info-item"><small>Experience</small><strong>${student.experience || "-"}</strong></div>
                <div class="info-item"><small>Registered</small><strong>${
                  student.created_at ? new Date(student.created_at).toLocaleDateString() : "-"
                }</strong></div>
              </div>
              <div class="mt-1"><small style="color:#6f809c;">Motivation</small><p>${student.motivation || "Not provided"}</p></div>
              <div class="mt-1"><small style="color:#6f809c;">Courses</small><p>${courses.join(", ") || "No courses listed"}</p></div>
            </div>
          </div>
        `;
      }

      document.getElementById("studentDetailsModal")?.classList.add("show");
    } catch (error) {
      alert(error.message);
    }
  }

  function closeModal() {
    document.getElementById("studentDetailsModal")?.classList.remove("show");
  }

  window.closeStudentDetails = closeModal;

  document.getElementById("closeStudentDetails")?.addEventListener("click", closeModal);
  document.getElementById("studentDetailsModal")?.addEventListener("click", function (event) {
    if (event.target.id === "studentDetailsModal") {
      closeModal();
    }
  });

  if (searchInput) {
    searchInput.addEventListener("input", function () {
      currentPage = 1;
      fetchStudents();
    });
  }

  sortField?.addEventListener("change", function () {
    currentPage = 1;
    fetchStudents();
  });

  sortOrder?.addEventListener("change", function () {
    currentPage = 1;
    fetchStudents();
  });

  prevBtn?.addEventListener("click", function () {
    if (currentPage > 1) {
      currentPage -= 1;
      fetchStudents();
    }
  });

  nextBtn?.addEventListener("click", function () {
    if (currentPage < totalPages) {
      currentPage += 1;
      fetchStudents();
    }
  });

  document.getElementById("logoutBtn")?.addEventListener("click", logout);

  document.getElementById("loginForm")?.addEventListener("submit", async function (event) {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const button = document.getElementById("loginBtn");
    const originalText = button.textContent;

    button.disabled = true;
    button.textContent = "Signing in...";

    try {
      const payload = await window.apiFetch("/api/teachers/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      localStorage.setItem("teacherToken", payload.token || "");
      localStorage.setItem("teacherData", JSON.stringify(payload.teacher || {}));
      localStorage.setItem("teacherLoggedIn", "true");

      setLoginMessage("Login successful.", "success");

      const teacherName = document.getElementById("teacherName");
      if (teacherName) {
        const teacher = payload.teacher || {};
        teacherName.textContent = `${teacher.first_name || "Teacher"} ${teacher.last_name || ""}`.trim();
      }

      loginSection?.classList.add("hidden");
      dashboard?.classList.remove("hidden");
      fetchStudents();
    } catch (error) {
      setLoginMessage(error.message, "error");
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });

  const teacherData = localStorage.getItem("teacherData");
  if (teacherData) {
    try {
      const teacher = JSON.parse(teacherData);
      const teacherName = document.getElementById("teacherName");
      if (teacherName) {
        teacherName.textContent = `${teacher.first_name || "Teacher"} ${teacher.last_name || ""}`.trim();
      }
    } catch (_error) {
      // ignore parse issues
    }
  }

  if (localStorage.getItem("teacherLoggedIn") === "true" && getToken()) {
    loginSection?.classList.add("hidden");
    dashboard?.classList.remove("hidden");
    fetchStudents();
  }
})();
