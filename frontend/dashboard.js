const API_BASE_URL = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
  ? "http://localhost:5000"
  : "https://bulk-email-sender-uaig.onrender.com";

// Recipient state
let recipients = [];
let quill = null;
let activeTemplateId = "";
let currentPreviewIndex = 0;
let sendingInProgress = false;
let cancelSendingRequested = false;

document.addEventListener("DOMContentLoaded", () => {
  // 1. Auth protection & user details
  async function checkAuth() {
    // Check URL parameters for OAuth session token
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get("token");
    if (tokenFromUrl) {
      localStorage.setItem("auth_token", tokenFromUrl);
      // Clean up parameters so token is not exposed in history/address bar
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    const token = localStorage.getItem("auth_token");
    const headers = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      // 10-second timeout for slow networks
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(`${API_BASE_URL}/user`, { 
        headers,
        credentials: "include",
        signal: controller.signal
      });
      clearTimeout(timeoutId);

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
      showToast("Authentication connection error. Retrying session verification...", "error");
      
      // Attempt retry once on mobile slow network
      setTimeout(async () => {
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
            showToast("Session recovered successfully.", "success");
            const userEmailSpan = document.getElementById("userEmail");
            const userAvatarImg = document.getElementById("userAvatar");
            if (userEmailSpan) {
              userEmailSpan.textContent = data.user.emails?.[0]?.value || data.user.displayName || "Gmail User";
            }
            if (userAvatarImg && data.user.photos?.[0]?.value) {
              userAvatarImg.src = data.user.photos[0].value;
            }
          }
        } catch (retryErr) {
          localStorage.removeItem("auth_token");
          window.location.href = "index.html";
        }
      }, 3000);
    }
  }

  checkAuth();

  // 2. Initialize Quill Rich Text Editor
  quill = new Quill('#editor', {
    theme: 'snow',
    placeholder: 'Craft your HTML email here...',
    modules: {
      toolbar: [
        [{ 'header': [1, 2, 3, false] }],
        ['bold', 'italic', 'underline'],
        [{ 'color': [] }, { 'background': [] }],
        ['link', 'image'],
        [{ 'align': [] }],
        ['clean']
      ]
    }
  });

  // 3. UI Element References
  const csvFileInput = document.getElementById("csvFileInput");
  const uploadZone = document.getElementById("uploadZone");
  const fileInfoBadge = document.getElementById("fileInfoBadge");
  const fileNameDisplay = document.getElementById("fileNameDisplay");
  const removeFileBtn = document.getElementById("removeFileBtn");
  const recipientTableBody = document.getElementById("recipientTableBody");
  const emptyState = document.getElementById("emptyState");
  const recipientCountBadge = document.getElementById("recipientCountBadge");
  const uniqueCountSpan = document.getElementById("uniqueCount");

  const templateSelector = document.getElementById("templateSelector");
  const saveTemplateBtn = document.getElementById("saveTemplateBtn");
  const deleteTemplateBtn = document.getElementById("deleteTemplateBtn");
  const newTemplateBtn = document.getElementById("newTemplateBtn");

  const varBadges = document.querySelectorAll(".var-badge");
  const subjectInput = document.getElementById("subjectInput");

  const previewBtn = document.getElementById("previewBtn");
  const sendBtn = document.getElementById("sendBtn");
  const logoutBtn = document.getElementById("logoutBtn");

  // Modal elements
  const previewModal = document.getElementById("previewModal");
  const closeModalBtn = document.getElementById("closeModalBtn");
  const previewTo = document.getElementById("previewTo");
  const previewSubject = document.getElementById("previewSubject");
  const previewBody = document.getElementById("previewBody");
  const prevRecipientBtn = document.getElementById("prevRecipientBtn");
  const nextRecipientBtn = document.getElementById("nextRecipientBtn");
  const previewIndexLabel = document.getElementById("previewIndexLabel");

  // Progress UI
  const progressSection = document.getElementById("progressSection");
  const progressBarFill = document.getElementById("progressBarFill");
  const progressCountLabel = document.getElementById("progressCountLabel");
  const progressPercentLabel = document.getElementById("progressPercentLabel");
  const progressSuccessCount = document.getElementById("progressSuccessCount");
  const progressFailedCount = document.getElementById("progressFailedCount");
  const cancelSendingBtn = document.getElementById("cancelSendingBtn");
  const resultLog = document.getElementById("resultLog");

  // 4. Toast Notifications
  function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <span>${message}</span>
    `;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(20px)";
      setTimeout(() => {
        toast.remove();
      }, 300);
    }, 4000);
  }

  // 5. CSV Drag & Drop Upload Handlers
  uploadZone.addEventListener("click", () => csvFileInput.click());

  uploadZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    uploadZone.classList.add("dragover");
  });

  uploadZone.addEventListener("dragleave", () => {
    uploadZone.classList.remove("dragover");
  });

  uploadZone.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadZone.classList.remove("dragover");
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      csvFileInput.files = files;
      handleCSVUpload(files[0]);
    }
  });

  csvFileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handleCSVUpload(e.target.files[0]);
    }
  });

  removeFileBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    resetCSVState();
  });

  function resetCSVState() {
    csvFileInput.value = "";
    recipients = [];
    fileInfoBadge.style.display = "none";
    uploadZone.style.display = "flex";
    recipientTableBody.innerHTML = "";
    emptyState.style.display = "block";
    recipientCountBadge.textContent = "0";
    uniqueCountSpan.textContent = "0";
    showToast("CSV file removed.", "info");
  }

  // Find column in row with case-insensitive synonym mapping
  function getCSVColumnValue(row, synonyms) {
    const keys = Object.keys(row);
    for (const syn of synonyms) {
      const matchedKey = keys.find(k => k.trim().toLowerCase() === syn.toLowerCase());
      if (matchedKey && row[matchedKey] !== undefined) {
        return row[matchedKey].trim();
      }
    }
    return "";
  }

  function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
  }

  function handleCSVUpload(file) {
    if (!file.name.endsWith(".csv")) {
      showToast("Please upload a valid CSV file.", "error");
      return;
    }

    Papa.parse(file, {
      header: true,
      skipEmptyLines: true,
      complete: function (results) {
        const parsedRows = results.data;
        if (!parsedRows || parsedRows.length === 0) {
          showToast("CSV file appears to be empty.", "error");
          return;
        }

        // CSV Column Synonyms
        const synonymsName = ["name", "fullname", "first name", "first_name", "username", "recipient name", "recipient"];
        const synonymsEmail = ["email", "email address", "mail", "to", "email_address"];
        const synonymsCompany = ["company", "organization", "company name", "company_name", "org", "employer"];
        const synonymsPhone = ["phone", "phone number", "phone_number", "mobile", "contact", "telephone", "phone_no"];

        const tempRecipients = [];
        const seenEmails = new Set();
        let duplicateCount = 0;
        let invalidCount = 0;

        parsedRows.forEach((row) => {
          const email = getCSVColumnValue(row, synonymsEmail);
          const name = getCSVColumnValue(row, synonymsName);
          const company = getCSVColumnValue(row, synonymsCompany);
          const phone = getCSVColumnValue(row, synonymsPhone);

          if (!email) {
            invalidCount++;
            return;
          }

          if (!validateEmail(email)) {
            invalidCount++;
            return;
          }

          if (seenEmails.has(email.toLowerCase())) {
            duplicateCount++;
            return;
          }

          seenEmails.add(email.toLowerCase());
          tempRecipients.push({
            name: name || "Customer",
            email: email,
            company: company || "Your Company",
            phone: phone || "N/A"
          });
        });

        if (tempRecipients.length === 0) {
          showToast("No valid, unique recipients found in CSV.", "error");
          resetCSVState();
          return;
        }

        recipients = tempRecipients;

        // UI Updates
        fileNameDisplay.textContent = `${file.name} (${recipients.length} recipients)`;
        uploadZone.style.display = "none";
        fileInfoBadge.style.display = "flex";

        renderRecipientTable();
        showToast(`Parsed ${parsedRows.length} rows successfully. Valid: ${recipients.length}, Duplicates ignored: ${duplicateCount}, Invalid: ${invalidCount}`, "success");
      },
      error: function (err) {
        console.error("CSV Parse Error:", err);
        showToast("Failed to parse CSV file.", "error");
      }
    });
  }

  function renderRecipientTable() {
    recipientTableBody.innerHTML = "";
    emptyState.style.display = "none";

    recipients.forEach((rec, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${rec.name}</td>
        <td><strong>${rec.email}</strong></td>
        <td>${rec.company}</td>
        <td>${rec.phone}</td>
        <td><span class="status-indicator valid">Valid</span></td>
      `;
      recipientTableBody.appendChild(tr);
    });

    recipientCountBadge.textContent = recipients.length;
    uniqueCountSpan.textContent = recipients.length;
  }

  // 6. Templates System (localStorage)
  const defaultTemplates = [
    {
      id: "tpl_welcome",
      name: "Welcome Onboarding",
      subject: "Welcome {{name}} to {{company}}!",
      body: `<p>Hello <strong>{{name}}</strong>,</p><p><br></p><p>Thank you for joining <strong>{{company}}</strong>. We are thrilled to have you with us!</p><p>We will be reaching out shortly at <strong>{{phone}}</strong> to finalize your account setup.</p><p><br></p><p>Regards,</p><p><strong>Team {{company}}</strong></p>`
    },
    {
      id: "tpl_newsletter",
      name: "Monthly Newsletter",
      subject: "Important updates for {{name}}",
      body: `<p>Hello <strong>{{name}}</strong>,</p><p><br></p><p>Here are the latest updates from <strong>{{company}}</strong>. Let us know if you have any questions or feedback!</p><p><br></p><p>Regards,</p><p><strong>Team {{company}}</strong></p>`
    }
  ];

  function loadTemplates() {
    let saved = localStorage.getItem("bulk_email_templates");
    if (!saved) {
      localStorage.setItem("bulk_email_templates", JSON.stringify(defaultTemplates));
      saved = JSON.stringify(defaultTemplates);
    }
    const templates = JSON.parse(saved);

    // Build Selector dropdown options
    templateSelector.innerHTML = `<option value="" disabled selected>-- Choose Email Template --</option>`;
    templates.forEach((tpl) => {
      const opt = document.createElement("option");
      opt.value = tpl.id;
      opt.textContent = tpl.name;
      templateSelector.appendChild(opt);
    });

    if (activeTemplateId) {
      templateSelector.value = activeTemplateId;
    }
  }

  loadTemplates();

  templateSelector.addEventListener("change", (e) => {
    activeTemplateId = e.target.value;
    const templates = JSON.parse(localStorage.getItem("bulk_email_templates") || "[]");
    const tpl = templates.find(t => t.id === activeTemplateId);
    if (tpl) {
      subjectInput.value = tpl.subject;
      quill.root.innerHTML = tpl.body;
      showToast(`Template "${tpl.name}" loaded.`, "success");
    }
  });

  newTemplateBtn.addEventListener("click", () => {
    activeTemplateId = "";
    templateSelector.value = "";
    subjectInput.value = "";
    quill.root.innerHTML = "";
    showToast("Cleared inputs. Ready to create a new template.", "info");
  });

  saveTemplateBtn.addEventListener("click", () => {
    const subject = subjectInput.value.trim();
    const body = quill.root.innerHTML;

    if (!subject || quill.getText().trim() === "") {
      showToast("Subject and Body are required to save a template.", "error");
      return;
    }

    const templates = JSON.parse(localStorage.getItem("bulk_email_templates") || "[]");

    if (activeTemplateId) {
      // Edit existing template
      const idx = templates.findIndex(t => t.id === activeTemplateId);
      if (idx !== -1) {
        templates[idx].subject = subject;
        templates[idx].body = body;
        localStorage.setItem("bulk_email_templates", JSON.stringify(templates));
        showToast(`Template "${templates[idx].name}" updated.`, "success");
      }
    } else {
      // Create new template
      const name = prompt("Enter a name for your new template:");
      if (!name || name.trim() === "") {
        showToast("Template save cancelled or invalid name.", "warning");
        return;
      }

      const newId = "tpl_" + Date.now();
      const newTpl = {
        id: newId,
        name: name.trim(),
        subject: subject,
        body: body
      };

      templates.push(newTpl);
      localStorage.setItem("bulk_email_templates", JSON.stringify(templates));
      activeTemplateId = newId;
      loadTemplates();
      showToast(`Template "${name}" saved successfully.`, "success");
    }
  });

  deleteTemplateBtn.addEventListener("click", () => {
    if (!activeTemplateId) {
      showToast("Select a template to delete first.", "warning");
      return;
    }

    const templates = JSON.parse(localStorage.getItem("bulk_email_templates") || "[]");
    const tpl = templates.find(t => t.id === activeTemplateId);

    if (tpl && confirm(`Are you sure you want to delete template "${tpl.name}"?`)) {
      const updated = templates.filter(t => t.id !== activeTemplateId);
      localStorage.setItem("bulk_email_templates", JSON.stringify(updated));
      activeTemplateId = "";
      subjectInput.value = "";
      quill.root.innerHTML = "";
      loadTemplates();
      showToast("Template deleted successfully.", "success");
    }
  });

  // 7. Dynamic Variable Badges
  varBadges.forEach((badge) => {
    badge.addEventListener("click", () => {
      const placeholder = badge.getAttribute("data-var");
      
      // Determine where cursor/focus is: Subject or Quill
      if (document.activeElement === subjectInput) {
        const start = subjectInput.selectionStart;
        const end = subjectInput.selectionEnd;
        const text = subjectInput.value;
        subjectInput.value = text.substring(0, start) + placeholder + text.substring(end);
        subjectInput.focus();
        subjectInput.setSelectionRange(start + placeholder.length, start + placeholder.length);
      } else {
        // Insert into Quill editor
        quill.focus();
        const range = quill.getSelection();
        if (range) {
          quill.insertText(range.index, placeholder);
          quill.setSelection(range.index + placeholder.length);
        } else {
          quill.insertText(quill.getLength() - 1, placeholder);
        }
      }
    });
  });

  // 8. Placeholders Interpolation Helper
  function interpolate(text, recipient) {
    if (!text) return "";
    return text
      .replace(/\{\{name\}\}/gi, recipient.name || "")
      .replace(/\{\{email\}\}/gi, recipient.email || "")
      .replace(/\{\{company\}\}/gi, recipient.company || "")
      .replace(/\{\{phone\}\}/gi, recipient.phone || "");
  }

  // 9. Interactive Email Preview Modal
  previewBtn.addEventListener("click", () => {
    if (recipients.length === 0) {
      showToast("Please upload a CSV file to preview recipients.", "warning");
      return;
    }

    const subject = subjectInput.value.trim();
    if (!subject || quill.getText().trim() === "") {
      showToast("Please enter a subject and body to preview.", "warning");
      return;
    }

    currentPreviewIndex = 0;
    openPreviewModal();
  });

  function openPreviewModal() {
    renderPreviewRecipient();
    previewModal.classList.add("active");
  }

  function closePreviewModal() {
    previewModal.classList.remove("active");
  }

  closeModalBtn.addEventListener("click", closePreviewModal);
  previewModal.addEventListener("click", (e) => {
    if (e.target === previewModal) closePreviewModal();
  });

  function renderPreviewRecipient() {
    const rec = recipients[currentPreviewIndex];
    previewTo.textContent = `${rec.name} <${rec.email}>`;
    
    const rawSubject = subjectInput.value;
    const rawBody = quill.root.innerHTML;

    previewSubject.textContent = interpolate(rawSubject, rec);
    previewBody.innerHTML = interpolate(rawBody, rec);

    previewIndexLabel.textContent = `Recipient ${currentPreviewIndex + 1} of ${recipients.length}`;

    // Disable cycle buttons as needed
    prevRecipientBtn.disabled = currentPreviewIndex === 0;
    nextRecipientBtn.disabled = currentPreviewIndex === recipients.length - 1;
  }

  prevRecipientBtn.addEventListener("click", () => {
    if (currentPreviewIndex > 0) {
      currentPreviewIndex--;
      renderPreviewRecipient();
    }
  });

  nextRecipientBtn.addEventListener("click", () => {
    if (currentPreviewIndex < recipients.length - 1) {
      currentPreviewIndex++;
      renderPreviewRecipient();
    }
  });

  // 10. Sequential Sending Loop
  sendBtn.addEventListener("click", async () => {
    if (recipients.length === 0) {
      showToast("Please upload a CSV file with recipients first.", "error");
      return;
    }

    const subject = subjectInput.value.trim();
    if (!subject || quill.getText().trim() === "") {
      showToast("Subject and message body cannot be empty.", "error");
      return;
    }

    if (sendingInProgress) return;

    sendingInProgress = true;
    cancelSendingRequested = false;
    sendBtn.disabled = true;
    previewBtn.disabled = true;

    // Reset Progress State
    progressSection.style.display = "flex";
    progressBarFill.style.width = "0%";
    progressCountLabel.textContent = `Sending 0 / ${recipients.length}`;
    progressPercentLabel.textContent = "0%";
    progressSuccessCount.textContent = "0";
    progressFailedCount.textContent = "0";
    resultLog.innerHTML = `<div class="log-entry info">Starting mail merge sending loop...</div>`;

    const attachmentFile = document.getElementById("attachmentFileInput").files[0];
    let successCount = 0;
    let failedCount = 0;

    for (let i = 0; i < recipients.length; i++) {
      if (cancelSendingRequested) {
        resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry error">Sending process was cancelled by user.</div>`);
        resultLog.scrollTop = resultLog.scrollHeight;
        showToast("Bulk sending cancelled.", "warning");
        break;
      }

      const rec = recipients[i];
      const personalizedSubject = interpolate(subject, rec);
      const personalizedBody = interpolate(quill.root.innerHTML, rec);

      resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry info">Sending to ${rec.email}...</div>`);
      resultLog.scrollTop = resultLog.scrollHeight;

      try {
        const formData = new FormData();
        // Backend takes JSON parsed string of emails array
        formData.append("emails", JSON.stringify([rec.email]));
        formData.append("subject", personalizedSubject);
        formData.append("message", personalizedBody);
        
        if (attachmentFile) {
          formData.append("attachment", attachmentFile);
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

        if (data.success) {
          successCount++;
          resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry success">[✓] Successfully sent to ${rec.email}</div>`);
        } else {
          failedCount++;
          const reason = data.failedList?.[0]?.error || data.error || data.message || "Failed";
          resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry error">[✗] Failed for ${rec.email}: ${reason}</div>`);
        }
      } catch (err) {
        console.error(`Error sending to ${rec.email}:`, err);
        failedCount++;
        resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry error">[✗] Network/Server error for ${rec.email}</div>`);
      }

      // Update UI Progress for each step
      const processed = i + 1;
      const percent = Math.round((processed / recipients.length) * 100);
      progressBarFill.style.width = `${percent}%`;
      progressCountLabel.textContent = `Sending ${processed} / ${recipients.length}`;
      progressPercentLabel.textContent = `${percent}%`;
      progressSuccessCount.textContent = successCount;
      progressFailedCount.textContent = failedCount;
      resultLog.scrollTop = resultLog.scrollHeight;
    }

    // Finished Sending
    resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry info"><strong>Task finished. Success: ${successCount}, Failed: ${failedCount}</strong></div>`);
    resultLog.scrollTop = resultLog.scrollHeight;

    if (cancelSendingRequested) {
      showToast(`Campaign halted. ${successCount} sent, ${failedCount} failed.`, "warning");
    } else {
      showToast(`Campaign completed! ${successCount} sent, ${failedCount} failed.`, "success");
    }

    sendingInProgress = false;
    sendBtn.disabled = false;
    previewBtn.disabled = false;
  });

  cancelSendingBtn.addEventListener("click", () => {
    if (sendingInProgress) {
      cancelSendingRequested = true;
      resultLog.insertAdjacentHTML("beforeend", `<div class="log-entry error">Cancellation request submitted...</div>`);
      resultLog.scrollTop = resultLog.scrollHeight;
    }
  });

  // 11. Logout handler
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
