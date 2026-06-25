if (window.location.hostname === "127.0.0.1") {
  window.location.hostname = "localhost";
}

const API_BASE_URL = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
  ? `${window.location.protocol}//${window.location.hostname}:5000`
  : "https://bulk-email-sender-uaig.onrender.com";

document.addEventListener("DOMContentLoaded", () => {
  let currentPage = 1;
  const recordsPerPage = 50;

  // 1. Auth protection & user details
  async function checkAuth() {
    const token = localStorage.getItem("auth_token");
    const headers = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/user`, { 
        headers,
        credentials: "include"
      });
      const data = await response.json();
      if (!data.loggedIn) {
        localStorage.removeItem("auth_token");
        window.location.href = "index.html";
      } else {
        // Populate user info badge
        const userEmailSpan = document.getElementById("userEmail");
        const userAvatarImg = document.getElementById("userAvatar");
        if (userEmailSpan) {
          userEmailSpan.textContent = data.user.emails?.[0]?.value || data.user.displayName || "Gmail User";
        }
        if (userAvatarImg && data.user.photos?.[0]?.value) {
          userAvatarImg.src = data.user.photos[0].value;
        }
      }
    } catch (error) {
      console.error("Auth verification failed:", error);
      localStorage.removeItem("auth_token");
      window.location.href = "index.html";
    }
  }

  checkAuth();

  // Toast Notifications Helper
  function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(20px)";
      setTimeout(() => {
        toast.remove();
      }, 300);
    }, 4000);
  }

  // 2. Fetch and render stats
  async function fetchStats() {
    try {
      const token = localStorage.getItem("auth_token");
      const headers = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const response = await fetch(`${API_BASE_URL}/api/stats`, { headers, credentials: "include" });
      const stats = await response.json();

      document.getElementById("statTotal").textContent = stats.total || 0;
      document.getElementById("statSent").textContent = stats.sent || 0;
      document.getElementById("statFailed").textContent = stats.failed || 0;
      document.getElementById("statOpened").textContent = stats.opened || 0;
      document.getElementById("statClicked").textContent = stats.clicked || 0;

      // Calculate rates
      const openRate = stats.sent > 0 ? Math.round((stats.opened / stats.sent) * 100) : 0;
      const clickRate = stats.sent > 0 ? Math.round((stats.clicked / stats.sent) * 100) : 0;

      document.getElementById("rateOpen").textContent = `Open Rate: ${openRate}%`;
      document.getElementById("rateClick").textContent = `Click Rate: ${clickRate}%`;
    } catch (error) {
      console.error("Failed to fetch statistics:", error);
      showToast("Error loading stats.", "error");
    }
  }

  // 3. Fetch and render email logs
  async function fetchLogs() {
    const search = document.getElementById("searchInput").value.trim();
    const filterStatus = document.getElementById("statusFilter").value;
    const tbody = document.getElementById("historyTableBody");
    const emptyState = document.getElementById("emptyState");

    try {
      const token = localStorage.getItem("auth_token");
      const headers = {};
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const queryParams = new URLSearchParams();
      if (search) queryParams.append("search", search);
      if (filterStatus) queryParams.append("status", filterStatus);
      queryParams.append("page", currentPage);
      queryParams.append("limit", recordsPerPage);

      const response = await fetch(`${API_BASE_URL}/api/history?${queryParams.toString()}`, { 
        headers, 
        credentials: "include" 
      });
      const data = await response.json();

      // Show/hide persistent warning banner based on backend persistent flag
      const warningBanner = document.getElementById("storageWarning");
      if (warningBanner) {
        warningBanner.style.display = (data.persistent === false) ? "flex" : "none";
      }

      tbody.innerHTML = "";

      if (!data.history || data.history.length === 0) {
        emptyState.style.display = "block";
        
        // Reset pagination UI
        document.getElementById("paginationTotal").textContent = "0";
        document.getElementById("paginationRange").textContent = "0-0";
        document.getElementById("currentPageNum").textContent = "Page 1";
        document.getElementById("prevPageBtn").disabled = true;
        document.getElementById("nextPageBtn").disabled = true;
        return;
      }

      emptyState.style.display = "none";

      data.history.forEach((row) => {
        const tr = document.createElement("tr");

        // Format dates
        const sentTime = new Date(row.sent_at).toLocaleString();
        const openTime = row.opened_at ? new Date(row.opened_at).toLocaleString() : "-";
        const clickTime = row.clicked_at ? new Date(row.clicked_at).toLocaleString() : "-";

        // Determine precise status tag
        let statusText = row.status;
        let tagClass = row.status.toLowerCase();
        if (row.status === "Sent") {
          if (row.clicked_at) {
            statusText = "Clicked";
            tagClass = "clicked";
          } else if (row.opened_at) {
            statusText = row.is_bot_open ? "Opened (Scanner/Bot)" : "Opened (Human)";
            tagClass = row.is_bot_open ? "opened-bot" : "opened";
          }
        }

        // Handle error column
        let errorContent = "-";
        if (row.error_message) {
          const truncated = row.error_message.length > 25 ? row.error_message.substring(0, 22) + "..." : row.error_message;
          errorContent = `<span class="tooltip">${truncated}<span class="tooltiptext">${row.error_message}</span></span>`;
        }

        tr.innerHTML = `
          <td>${sentTime}</td>
          <td><strong>${row.recipient_email}</strong></td>
          <td>${row.subject}</td>
          <td><span class="status-tag ${tagClass}">${statusText}</span></td>
          <td>${openTime}</td>
          <td>${clickTime}</td>
          <td>${errorContent}</td>
        `;
        tbody.appendChild(tr);
      });

      // Update pagination UI elements
      const total = data.total || 0;
      document.getElementById("paginationTotal").textContent = total;

      const startRecord = total > 0 ? (currentPage - 1) * recordsPerPage + 1 : 0;
      const endRecord = Math.min(currentPage * recordsPerPage, total);
      document.getElementById("paginationRange").textContent = `${startRecord}-${endRecord}`;
      document.getElementById("currentPageNum").textContent = `Page ${currentPage}`;

      const prevBtn = document.getElementById("prevPageBtn");
      const nextBtn = document.getElementById("nextPageBtn");

      prevBtn.disabled = currentPage === 1;
      nextBtn.disabled = endRecord >= total;

    } catch (error) {
      console.error("Failed to fetch logs:", error);
      showToast("Error loading email history.", "error");
    }
  }

  // Initial load
  fetchStats();
  fetchLogs();

  // 4. Setup event listeners
  document.getElementById("refreshBtn").addEventListener("click", () => {
    fetchStats();
    fetchLogs();
    showToast("Email history refreshed.", "success");
  });

  // Debounced search
  let searchTimeout = null;
  document.getElementById("searchInput").addEventListener("input", () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentPage = 1; // Reset to page 1 on fresh search
      fetchLogs();
    }, 400);
  });

  document.getElementById("statusFilter").addEventListener("change", () => {
    currentPage = 1; // Reset to page 1 on fresh filter
    fetchLogs();
  });

  // Pagination buttons listeners
  document.getElementById("prevPageBtn").addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--;
      fetchLogs();
    }
  });

  document.getElementById("nextPageBtn").addEventListener("click", () => {
    currentPage++;
    fetchLogs();
  });

  // 5. Logout logic
  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        const token = localStorage.getItem("auth_token");
        const headers = {};
        if (token) {
          headers["Authorization"] = `Bearer ${token}`;
        }
        const response = await fetch(`${API_BASE_URL}/logout`, { 
          headers: headers,
          credentials: "include" 
        });
        const data = await response.json();
        if (data.success) {
          localStorage.removeItem("auth_token");
          window.location.href = "index.html";
        } else {
          showToast("Logout failed.", "error");
        }
      } catch (error) {
        console.error("Logout error:", error);
        localStorage.removeItem("auth_token");
        window.location.href = "index.html";
      }
    });
  }
});
