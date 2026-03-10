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
  let currentEditId = null;

  function getToken() {
    return localStorage.getItem("adminToken");
  }

  function setLoginMessage(text, kind) {
    if (!loginMessage) return;
    loginMessage.textContent = text;
    loginMessage.className = `login-message ${kind || ""}`;
  }

  function showToast(message, ok) {
    const host = document.getElementById("toastHost");
    if (!host) return;

    const toast = document.createElement("div");
    toast.className = `toast ${ok ? "ok" : "err"}`;
    toast.textContent = message;
    host.appendChild(toast);

    setTimeout(() => toast.remove(), 2800);
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
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminData");
    localStorage.removeItem("adminLoggedIn");

    dashboard?.classList.add("hidden");
    loginSection?.classList.remove("hidden");
    document.getElementById("loginForm")?.reset();
    setLoginMessage("You have been logged out.", "success");
  }

  window.logout = logout;

  function updateMeta(students) {
    const totalNode = document.getElementById("totalStudents");
    const coursesNode = document.getElementById("totalCourses");
    const recentNode = document.getElementById("recentEntries");

    const uniqueCourses = new Set();
    students.forEach((student) => {
      safeCourses(student.courses).forEach((course) => uniqueCourses.add(course));
    });

    if (totalNode) totalNode.textContent = String(students.length);
    if (coursesNode) coursesNode.textContent = String(uniqueCourses.size);
    if (recentNode) {
      const latest = students.filter((item) => item.created_at).slice(0, 5);
      recentNode.innerHTML = "";

      latest.forEach((student) => {
        const li = document.createElement("li");
        li.textContent = `${student.firstName || ""} ${student.lastName || ""} - ${new Date(
          student.created_at
        ).toLocaleDateString()}`;
        recentNode.appendChild(li);
      });

      if (!latest.length) {
        recentNode.innerHTML = "<li>No recent registrations.</li>";
      }
    }
  }

  function renderRows(students) {
    if (!tableBody) return;

    tableBody.innerHTML = "";
    if (!students.length) {
      tableBody.innerHTML = '<tr><td colspan="8">No students found for your current filters.</td></tr>';
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
            <img src="${getProfilePictureURL(student.profilePictureUrl)}" class="avatar" alt="avatar">
            <span>${student.firstName || ""} ${student.lastName || ""}</span>
          </span>
        </td>
        <td>${student.email || "-"}</td>
        <td>${student.phone || "-"}</td>
        <td>${student.age || "-"}</td>
        <td><span class="badge muted">${courses.length} course(s)</span></td>
        <td>${registered}</td>
        <td>
          <span class="actions">
            <button class="btn-mini" data-view-id="${student.id}">View</button>
            <button class="btn-mini warn" data-edit-id="${student.id}">Edit</button>
            <button class="btn-mini danger" data-delete-id="${student.id}">Delete</button>
          </span>
        </td>
      `;

      tableBody.appendChild(row);
    });

    tableBody.querySelectorAll("[data-view-id]").forEach((button) => {
      button.addEventListener("click", function () {
        openStudentDetails(button.getAttribute("data-view-id"));
      });
    });

    tableBody.querySelectorAll("[data-edit-id]").forEach((button) => {
      button.addEventListener("click", function () {
        openEditModal(button.getAttribute("data-edit-id"));
      });
    });

    tableBody.querySelectorAll("[data-delete-id]").forEach((button) => {
      button.addEventListener("click", function () {
        deleteStudent(button.getAttribute("data-delete-id"));
      });
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
      updateMeta(students);

      if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
      if (prevBtn) prevBtn.disabled = currentPage <= 1;
      if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
    } catch (error) {
      if (tableBody) {
        tableBody.innerHTML = `<tr><td colspan="8">${error.message}</td></tr>`;
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
      showToast(error.message, false);
    }
  }

  function closeStudentDetails() {
    document.getElementById("studentDetailsModal")?.classList.remove("show");
  }

  window.closeStudentDetails = closeStudentDetails;

  async function openEditModal(id) {
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
      currentEditId = student.id;

      document.getElementById("editFirstName").value = student.firstName || "";
      document.getElementById("editLastName").value = student.lastName || "";
      document.getElementById("editEmail").value = student.email || "";
      document.getElementById("editPhone").value = student.phone || "";
      document.getElementById("editAge").value = student.age || "";
      document.getElementById("editEducation").value = student.education || "";
      document.getElementById("editExperience").value = student.experience || "";
      document.getElementById("editMotivation").value = student.motivation || "";
      document.getElementById("editCourses").value = courses.join(", ");
      document.getElementById("editProfileCurrent").textContent = student.profilePictureUrl
        ? `Current: ${student.profilePictureUrl}`
        : "No current profile picture";
      document.getElementById("editProfilePicture").value = "";
      document.getElementById("editStatus").textContent = "";

      document.getElementById("editStudentModal")?.classList.add("show");
    } catch (error) {
      showToast(error.message, false);
    }
  }

  function closeEditModal() {
    document.getElementById("editStudentModal")?.classList.remove("show");
    currentEditId = null;
  }

  window.closeEditModal = closeEditModal;

  async function saveEdit(event) {
    event.preventDefault();
    if (!currentEditId) return;

    const token = getToken();
    if (!token) {
      logout();
      return;
    }

    const form = document.getElementById("editStudentForm");
    const status = document.getElementById("editStatus");
    const button = document.getElementById("saveEditBtn");
    const originalText = button.textContent;

    const formData = new FormData();
    formData.append("firstName", document.getElementById("editFirstName").value.trim());
    formData.append("lastName", document.getElementById("editLastName").value.trim());
    formData.append("email", document.getElementById("editEmail").value.trim());
    formData.append("phone", document.getElementById("editPhone").value.trim());

    const ageValue = document.getElementById("editAge").value;
    if (ageValue) formData.append("age", ageValue);

    formData.append("education", document.getElementById("editEducation").value.trim());
    formData.append("experience", document.getElementById("editExperience").value.trim());
    formData.append("motivation", document.getElementById("editMotivation").value.trim());

    const courses = document
      .getElementById("editCourses")
      .value.split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    courses.forEach((course) => formData.append("courses", course));

    const file = document.getElementById("editProfilePicture").files?.[0];
    if (file) {
      formData.append("profilePicture", file);
    }

    button.disabled = true;
    button.textContent = "Saving...";

    try {
      const response = await fetch(`${window.API_BASE_URL}/api/students/${currentEditId}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`
        },
        body: formData
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || "Failed to update student");
      }

      if (status) {
        status.className = "status ok";
        status.textContent = payload.message || "Student updated successfully.";
      }

      showToast("Student record updated.", true);
      setTimeout(function () {
        closeEditModal();
        fetchStudents();
      }, 700);
    } catch (error) {
      if (status) {
        status.className = "status err";
        status.textContent = error.message;
      }
      showToast(error.message, false);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  }

  async function deleteStudent(id) {
    const token = getToken();
    if (!token) {
      logout();
      return;
    }

    const confirmed = window.confirm("Delete this student record permanently?");
    if (!confirmed) return;

    try {
      const payload = await window.apiFetch(`/api/students/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` }
      });

      showToast(payload.message || "Student deleted.", true);
      fetchStudents();
    } catch (error) {
      showToast(error.message, false);
    }
  }

  async function exportStudents(format) {
    const token = getToken();
    if (!token) {
      logout();
      return;
    }

    const endpoint = format === "pdf" ? "/api/students/export/pdf" : "/api/students/export/csv";

    try {
      const response = await fetch(`${window.API_BASE_URL}${endpoint}`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });

      if (!response.ok) {
        let message = `Export failed (${response.status})`;
        try {
          const data = await response.json();
          message = data.error || message;
        } catch (_error) {
          // ignore json parse error
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const filename = format === "pdf" ? "pima-students.pdf" : "pima-students.csv";
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);

      showToast(`Exported ${filename}`, true);
    } catch (error) {
      showToast(error.message, false);
    }
  }

  window.exportStudents = exportStudents;

  // Events
  document.getElementById("loginForm")?.addEventListener("submit", async function (event) {
    event.preventDefault();

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const button = document.getElementById("loginBtn");
    const originalText = button.textContent;

    button.disabled = true;
    button.textContent = "Signing in...";

    try {
      const payload = await window.apiFetch("/api/admins/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });

      localStorage.setItem("adminToken", payload.token || "");
      localStorage.setItem("adminData", JSON.stringify(payload.admin || {}));
      localStorage.setItem("adminLoggedIn", "true");

      const nameNode = document.getElementById("adminName");
      if (nameNode) {
        const admin = payload.admin || {};
        nameNode.textContent = `${admin.first_name || "Admin"} ${admin.last_name || ""}`.trim();
      }

      setLoginMessage("Login successful.", "success");
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

  searchInput?.addEventListener("input", function () {
    currentPage = 1;
    fetchStudents();
  });

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
  document.getElementById("closeStudentDetails")?.addEventListener("click", closeStudentDetails);
  document.getElementById("studentDetailsModal")?.addEventListener("click", function (event) {
    if (event.target.id === "studentDetailsModal") {
      closeStudentDetails();
    }
  });

  document.getElementById("editStudentModal")?.addEventListener("click", function (event) {
    if (event.target.id === "editStudentModal") {
      closeEditModal();
    }
  });

  document.getElementById("editStudentForm")?.addEventListener("submit", saveEdit);
  document.getElementById("cancelEditBtn")?.addEventListener("click", closeEditModal);

  const adminData = localStorage.getItem("adminData");
  if (adminData) {
    try {
      const admin = JSON.parse(adminData);
      const adminName = document.getElementById("adminName");
      if (adminName) {
        adminName.textContent = `${admin.first_name || "Admin"} ${admin.last_name || ""}`.trim();
      }
    } catch (_error) {
      // ignore
    }
  }

  if (localStorage.getItem("adminLoggedIn") === "true" && getToken()) {
    loginSection?.classList.add("hidden");
    dashboard?.classList.remove("hidden");
    fetchStudents();
  }
})();
