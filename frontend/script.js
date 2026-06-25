if (window.location.hostname === "127.0.0.1") {
  window.location.hostname = "localhost";
}

const API_BASE_URL = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
  ? `${window.location.protocol}//${window.location.hostname}:5000`
  : "https://bulk-email-sender-uaig.onrender.com";

document.addEventListener("DOMContentLoaded", () => {
  // Auth Protection Guard
  async function checkAuth() {
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get("token");
    if (tokenFromUrl) {
      localStorage.setItem("auth_token", tokenFromUrl);
      window.history.replaceState({}, document.title, window.location.pathname);
    }

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
      }
    } catch (error) {
      console.error("Auth verification failed:", error);
      window.location.href = "index.html";
    }
  }

  // Run auth check on dashboard page
  if (window.location.pathname.includes("dashboard.html")) {
    checkAuth();
  }

  const sendBtn = document.getElementById("sendBtn");
  const loading = document.getElementById("loading");
  const result = document.getElementById("result");
  const logoutBtn = document.getElementById("logoutBtn");

  if (sendBtn) {
    sendBtn.addEventListener("click", async () => {
      const emailsText = document.getElementById("emails").value;
      const subject = document.getElementById("subject").value;
      const message = document.getElementById("message").value;
      const attachment = document.getElementById("attachment").files[0];

      if (!emailsText || !subject || !message) {
        alert("Please fill all fields");
        return;
      }

      const emails = emailsText
        .split("\n")
        .map(email => email.trim())
        .filter(email => email !== "");

      loading.style.display = "block";
      result.innerHTML = "";

      try {
        const formData = new FormData();
        formData.append("emails", JSON.stringify(emails));
        formData.append("subject", subject);
        formData.append("message", message);

        if (attachment) {
          formData.append("attachment", attachment);
        }

        const token = localStorage.getItem("auth_token");
        const headers = {};
        if (token) {
          headers["Authorization"] = `Bearer ${token}`;
        }

        const response = await fetch(`${API_BASE_URL}/send-emails`, {
          method: "POST",
          headers: headers,
          credentials: "include",
          body: formData
        });

        const data = await response.json();
        loading.style.display = "none";

        if (data.success) {
          result.innerHTML = ` Sent all ${data.sentCount} emails successfully!`;
        } else {
          let errorHtml = ` Failed to send ${data.failedCount || 0} email(s).`;
          if (data.failedList && data.failedList.length > 0) {
            const listItems = data.failedList
              .map(item => `<li><strong>${item.email}</strong>: ${item.error}</li>`)
              .join("");
            errorHtml += `<ul style="text-align:left; margin-top:10px; font-size:13px; color:#ffbfbf; padding-left:20px;">${listItems}</ul>`;
          } else {
            errorHtml += ` ${data.error || data.message || "Unknown error"}`;
          }
          result.innerHTML = errorHtml;
        }

      } catch (error) {
        console.error(error);
        loading.style.display = "none";
        result.innerHTML = " Failed To Send Emails";
      }
    });
  }

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
          alert("Logout failed");
        }
      } catch (error) {
        console.error("Logout error:", error);
        localStorage.removeItem("auth_token");
        window.location.href = "index.html";
      }
    });
  }
});