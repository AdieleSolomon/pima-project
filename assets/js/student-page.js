(function () {
  const loginSection = document.getElementById("loginSection");
  const dashboard = document.getElementById("dashboard");
  const loginForm = document.getElementById("loginForm");
  const loginMessage = document.getElementById("loginMessage");
  let currentStudent = null;
  let progressChart = null;

  function setMessage(text, kind) {
    if (!loginMessage) return;
    loginMessage.textContent = text;
    loginMessage.className = `login-message ${kind || ""}`;
  }

  function getProfilePictureURL(profilePictureUrl) {
    if (!profilePictureUrl) return "https://ui-avatars.com/api/?name=Student&background=0a2f63&color=fff&size=256";
    if (profilePictureUrl.startsWith("http")) return profilePictureUrl;
    if (profilePictureUrl.startsWith("/uploads/")) return `${window.API_BASE_URL}${profilePictureUrl}`;
    return `${window.API_BASE_URL}/uploads/${profilePictureUrl}`;
  }

  function safeArray(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;

    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed;
    } catch (_error) {
      return value.split(",").map((item) => item.trim()).filter(Boolean);
    }

    return [];
  }

  function logout() {
    localStorage.removeItem("studentToken");
    localStorage.removeItem("studentData");
    localStorage.removeItem("studentLoggedIn");
    currentStudent = null;

    if (dashboard) dashboard.classList.add("hidden");
    if (loginSection) loginSection.classList.remove("hidden");

    if (loginForm) loginForm.reset();
    setMessage("You have been logged out.", "success");
  }

  window.logout = logout;

  function renderStudent(student) {
    if (!student) return;

    currentStudent = student;
    const courses = safeArray(student.courses);

    const setText = (id, value) => {
      const node = document.getElementById(id);
      if (node) node.textContent = value;
    };

    const displayName = `${student.firstName || ""} ${student.lastName || ""}`.trim() || "Student";
    setText("userName", displayName);
    setText("fullName", displayName);
    setText("studentId", student.id || "-");
    setText("profileEmail", student.email || "-");
    setText("profilePhone", student.phone || "-");
    setText("profileAge", student.age || "-");
    setText("profileEducation", student.education || "Not provided");
    setText("profileExperience", student.experience || "Not provided");
    setText("profileMotivation", student.motivation || "Not provided");
    setText("coursesCount", String(courses.length));
    setText("completedCourses", String(Math.max(0, Math.floor(courses.length * 0.35))));
    setText("progressPercentage", `${Math.min(95, 35 + courses.length * 5)}%`);

    const profileDate = student.created_at
      ? new Date(student.created_at).toLocaleDateString()
      : "-";
    setText("profileRegistration", profileDate);

    const image = document.getElementById("profileImage");
    if (image) {
      image.src = getProfilePictureURL(student.profilePictureUrl);
      image.alt = `${student.firstName || "Student"} profile`;
    }

    const avatar = document.getElementById("userAvatar");
    if (avatar) {
      avatar.src = getProfilePictureURL(student.profilePictureUrl);
      avatar.alt = "avatar";
    }

    const courseList = document.getElementById("courseList");
    if (courseList) {
      courseList.innerHTML = "";
      if (!courses.length) {
        courseList.innerHTML = '<li class="badge muted">No courses selected yet</li>';
      } else {
        courses.forEach((course) => {
          const li = document.createElement("li");
          li.className = "badge good";
          li.textContent = course;
          courseList.appendChild(li);
        });
      }
    }

    const activityList = document.getElementById("activityList");
    if (activityList) {
      activityList.innerHTML = "";
      const activityItems = [
        `Profile last synced on ${new Date().toLocaleString()}`,
        `${courses.length} program(s) currently selected`,
        "Portal access confirmed"
      ];

      activityItems.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        activityList.appendChild(li);
      });
    }

    const deadlineList = document.getElementById("deadlineList");
    if (deadlineList) {
      deadlineList.innerHTML = "";
      const deadlines = [
        "Tuition confirmation - Next 7 days",
        "Workshop safety orientation - This month",
        "Skills assessment round - Upcoming"
      ];

      deadlines.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        deadlineList.appendChild(li);
      });
    }

    if (window.Chart) {
      const chartNode = document.getElementById("progressChart");
      if (chartNode) {
        const completed = Math.max(0, Math.floor(courses.length * 0.35));
        const pending = Math.max(0, courses.length - completed);

        if (progressChart) {
          progressChart.destroy();
        }

        progressChart = new Chart(chartNode, {
          type: "doughnut",
          data: {
            labels: ["Completed", "In Progress"],
            datasets: [
              {
                data: [completed || 1, pending || 1],
                backgroundColor: ["#2f9b5b", "#d8a13a"],
                borderWidth: 0
              }
            ]
          },
          options: {
            plugins: { legend: { display: false } },
            cutout: "64%"
          }
        });
      }
    }
  }

  async function fetchStudentDetails() {
    const token = localStorage.getItem("studentToken");
    const raw = localStorage.getItem("studentData");

    if (!token || !raw) {
      logout();
      return;
    }

    let stored = null;
    try {
      stored = JSON.parse(raw);
    } catch (_error) {
      logout();
      return;
    }

    if (!stored?.id) {
      logout();
      return;
    }

    try {
      const payload = await window.apiFetch(`/api/students/${stored.id}`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`
        }
      });

      const student = payload.student || stored;
      localStorage.setItem("studentData", JSON.stringify(student));

      if (loginSection) loginSection.classList.add("hidden");
      if (dashboard) dashboard.classList.remove("hidden");
      renderStudent(student);
    } catch (error) {
      setMessage(error.message, "error");
      logout();
    }
  }

  if (loginForm) {
    loginForm.addEventListener("submit", async function (event) {
      event.preventDefault();
      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value;
      const button = document.getElementById("loginBtn");
      const originalText = button.textContent;

      button.disabled = true;
      button.textContent = "Signing in...";

      try {
        const payload = await window.apiFetch("/api/students/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });

        localStorage.setItem("studentToken", payload.token || "");
        localStorage.setItem("studentData", JSON.stringify(payload.student || {}));
        localStorage.setItem("studentLoggedIn", "true");

        setMessage("Login successful.", "success");
        await fetchStudentDetails();
      } catch (error) {
        setMessage(error.message, "error");
      } finally {
        button.disabled = false;
        button.textContent = originalText;
      }
    });
  }

  document.getElementById("logoutBtn")?.addEventListener("click", logout);

  const loggedIn = localStorage.getItem("studentLoggedIn") === "true";
  if (loggedIn) {
    fetchStudentDetails();
  }
})();
