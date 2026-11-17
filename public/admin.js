let token = sessionStorage.getItem("vireon_admin_token") || "";
let current = "overview";

const $ = selector => document.querySelector(selector);

const loginWrap = $("#login-wrap");
const dashboard = $("#dashboard");
const root = $("#page-content");

const titles = {
  overview: "Overview",
  clients: "Clients",
  invoices: "Invoices",
  transactions: "Income & Expenses",
  contacts: "Enquiries",
  logs: "Activity Logs"
};

const fields = {
  clients: [
    { name: "name", label: "Client name", required: true },
    { name: "company", label: "Company" },
    { name: "email", label: "Email", type: "email" },
    { name: "phone", label: "Phone" },
    { name: "notes", label: "Notes", type: "textarea" }
  ],
  invoices: [
    { name: "invoice_no", label: "Invoice number", required: true },
    { name: "client_name", label: "Client name", required: true },
    { name: "issue_date", label: "Issue date", type: "date", required: true },
    { name: "due_date", label: "Due date", type: "date" },
    { name: "currency", label: "Currency", type: "select", options: ["USD", "INR", "EUR", "GBP"] },
    { name: "amount", label: "Amount", type: "number", required: true },
    { name: "status", label: "Status", type: "select", options: ["Pending", "Paid", "Overdue"] },
    { name: "description", label: "Description", type: "textarea" }
  ],
  transactions: [
    { name: "type", label: "Type", type: "select", options: ["Income", "Expense"], required: true },
    { name: "entry_date", label: "Date", type: "date", required: true },
    { name: "category", label: "Category", required: true },
    { name: "amount", label: "Amount", type: "number", required: true },
    { name: "currency", label: "Currency", type: "select", options: ["USD", "INR", "EUR", "GBP"] },
    { name: "description", label: "Description", type: "textarea" }
  ]
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function money(value) {
  return Number(value || 0).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  });
}

async function api(path, options = {}) {
  const response = await fetch("/api/admin" + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token,
      ...options.headers
    }
  });

  const data = await response.json().catch(() => ({}));

  if (response.status === 401) {
    logout();
    throw new Error("Session expired. Please sign in again.");
  }

  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

function logout() {
  token = "";
  sessionStorage.removeItem("vireon_admin_token");
  dashboard.classList.add("hidden");
  loginWrap.classList.remove("hidden");
}

function showDashboard(email) {
  loginWrap.classList.add("hidden");
  dashboard.classList.remove("hidden");
  $("#admin-email").textContent = email || "";
  loadPage("overview");
}

// Login
$("#login-form").addEventListener("submit", async event => {
  event.preventDefault();

  $("#login-error").textContent = "";

  const data = Object.fromEntries(new FormData(event.target));

  try {
    const response = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || "Login failed.");
    }

    token = result.token;
    sessionStorage.setItem("vireon_admin_token", token);
    showDashboard(result.email);
  } catch (error) {
    $("#login-error").textContent = error.message;
  }
});

$("#logout").addEventListener("click", logout);

$("#side-nav").addEventListener("click", event => {
  const button = event.target.closest("button[data-page]");
  if (button && titles[button.dataset.page]) {
    loadPage(button.dataset.page);
  }
});

// Form field rendering
function renderField(field, value = "") {
  const name = escapeHtml(field.name);
  const label = escapeHtml(field.label);
  const required = field.required ? "required" : "";
  const safeValue = escapeHtml(value);

  if (field.type === "select") {
    const options = field.options.map(option =>
      `<option value="${escapeHtml(option)}" ${value === option ? "selected" : ""}>${escapeHtml(option)}</option>`
    ).join("");

    return `<label>${label}<select name="${name}" ${required}>${options}</select></label>`;
  }

  if (field.type === "textarea") {
    return `<label>${label}<textarea name="${name}" ${required}>${safeValue}</textarea></label>`;
  }

  return `<label>${label}<input name="${name}" type="${field.type || "text"}" value="${safeValue}" ${field.type === "number" ? 'step="0.01" min="0.01"' : ""} ${required}></label>`;
}

function formPanel(resource) {
  const editing = Boolean($("#record-id")?.value);
  const formFields = fields[resource];

  return `
    <div class="panel">
      <h2 id="form-heading">${editing ? "Edit record" : resource === "invoices" ? "Create invoice" : resource === "transactions" ? "Record income or expense" : "Add client"}</h2>
      <form id="record-form" class="form-grid">
        <input type="hidden" id="record-id" name="record_id">
        ${formFields.map(field => renderField(field)).join("")}
        <button class="primary" type="submit" id="save-button">${editing ? "Update record" : "Save record"}</button>
        <button type="button" id="cancel-edit" class="danger hidden">Cancel edit</button>
      </form>
      <p id="save-status" class="muted" aria-live="polite"></p>
    </div>
  `;
}

function stat(label, value) {
  return `
    <div class="stat">
      <small>${escapeHtml(label)}</small>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function table(rows, columns, resource = null, invoice = false) {
  if (!rows.length) {
    return `<div class="panel"><p class="muted">No records yet.</p></div>`;
  }

  return `
    <div class="panel">
      <h2>Records</h2>
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead>
            <tr>
              ${columns.map(column => `<th>${escapeHtml(column.replaceAll("_", " "))}</th>`).join("")}
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${rows.map(row => `
              <tr>
                ${columns.map(column => `<td>${escapeHtml(row[column] ?? "")}</td>`).join("")}
                <td>
                  ${resource ? `<button class="primary edit" data-id="${row.id}" data-resource="${resource}">Edit</button> ` : ""}
                  ${invoice ? `<button class="primary pdf" data-id="${row.id}">PDF</button> ` : ""}
                  ${resource ? `<button class="danger delete" data-id="${row.id}" data-resource="${resource}">Delete</button>` : ""}
                  ${!resource && !invoice ? "View only" : ""}
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// Monthly report
function reportPanel() {
  const year = new Date().getFullYear();

  return `
    <div class="panel">
      <h2>Monthly financial report</h2>
      <form id="report-form" class="form-grid">
        <label>Year
          <input type="number" name="year" min="2000" max="2100" value="${year}" required>
        </label>
        <button class="primary" type="submit">Load report</button>
      </form>
      <div id="report-results"><p class="muted">Select a year and load the report.</p></div>
    </div>
  `;
}

async function loadReport(year) {
  const target = $("#report-results");
  target.innerHTML = '<p class="muted">Loading report…</p>';

  try {
    const data = await api("/reports/monthly?year=" + encodeURIComponent(year));

    if (!data.rows.length) {
      target.innerHTML = '<p class="muted">No financial records for this year.</p>';
      return;
    }

    target.innerHTML = `
      <div style="overflow-x:auto">
        <table class="data-table">
          <thead>
            <tr>
              <th>Month</th>
              <th>Currency</th>
              <th>Income</th>
              <th>Expenses</th>
              <th>Profit</th>
            </tr>
          </thead>
          <tbody>
            ${data.rows.map(row => `
              <tr>
                <td>${escapeHtml(row.month)}</td>
                <td>${escapeHtml(row.currency)}</td>
                <td>${escapeHtml(money(row.income))}</td>
                <td>${escapeHtml(money(row.expenses))}</td>
                <td>${escapeHtml(money(Number(row.income) - Number(row.expenses)))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
      <p class="muted">Amounts are grouped by currency. No currency conversion is applied.</p>
    `;
  } catch (error) {
    target.innerHTML = `<p>${escapeHtml(error.message)}</p>`;
  }
}

// Main page loader
async function loadPage(page) {
  if (!titles[page]) return;

  current = page;
  $("#page-title").textContent = titles[page];

  document.querySelectorAll("#side-nav button").forEach(button => {
    button.classList.toggle("selected", button.dataset.page === page);
  });

  root.innerHTML = '<p class="muted">Loading…</p>';

  try {
    if (page === "overview") {
      const data = await api("/summary");

      root.innerHTML = `
        <div class="stats">
          ${stat("Total income (all currencies)", money(data.income))}
          ${stat("Total expenses (all currencies)", money(data.expenses))}
          ${stat("Net total (all currencies)", money(data.profit))}
          ${stat("Clients", data.clients)}
          ${stat("Invoices", data.invoices)}
          ${stat("Unpaid invoices", data.pending)}
        </div>
        <div class="panel">
          <h2>Currency-wise totals</h2>
          ${data.currencyTotals?.length ? `
            <div style="overflow-x:auto">
              <table class="data-table">
                <thead><tr><th>Currency</th><th>Income</th><th>Expenses</th><th>Profit</th></tr></thead>
                <tbody>
                  ${data.currencyTotals.map(row => `
                    <tr>
                      <td>${escapeHtml(row.currency)}</td>
                      <td>${money(row.income)}</td>
                      <td>${money(row.expenses)}</td>
                      <td>${money(Number(row.income) - Number(row.expenses))}</td>
                    </tr>
                  `).join("")}
                </tbody>
              </table>
            </div>
          ` : '<p class="muted">No transactions recorded yet.</p>'}
        </div>
        ${reportPanel()}
        <div class="panel">
          <h2>Management overview</h2>
          <p class="muted">Manage clients, invoices, financial transactions and incoming enquiries from this dashboard.</p>
        </div>
      `;

      return;
    }

    const endpoint = page === "transactions" ? "transactions" : page;
    const rows = await api("/" + endpoint);

    if (page === "clients") {
      root.innerHTML = formPanel("clients") +
        table(rows, ["name", "company", "email", "phone", "created_at"], "clients");
    } else if (page === "invoices") {
      root.innerHTML = formPanel("invoices") +
        table(rows, ["invoice_no", "client_name", "issue_date", "due_date", "currency", "amount", "status"], "invoices", true);
    } else if (page === "transactions") {
      root.innerHTML = formPanel("transactions") +
        table(rows, ["type", "entry_date", "category", "description", "amount", "currency"], "transactions");
    } else if (page === "contacts") {
      root.innerHTML = table(rows, ["name", "email", "company", "message", "created_at"]);
    } else if (page === "logs") {
      root.innerHTML = table(rows, ["action", "details", "created_at"]);
    }
  } catch (error) {
    root.innerHTML = `<div class="panel">${escapeHtml(error.message)}</div>`;
  }
}

// One delegated event listener for all page content
root.addEventListener("submit", async event => {
  if (event.target.id === "record-form") {
    event.preventDefault();

    const form = event.target;
    const resource = current === "transactions" ? "transactions" : current;
    const id = $("#record-id").value;
    const data = Object.fromEntries(new FormData(form));
    delete data.record_id;

    const button = $("#save-button");
    const status = $("#save-status");

    button.disabled = true;
    status.textContent = id ? "Updating record…" : "Saving record…";

    try {
      await api("/" + resource + (id ? "/" + id : ""), {
        method: id ? "PUT" : "POST",
        body: JSON.stringify(data)
      });

      await loadPage(current);
    } catch (error) {
      status.textContent = error.message;
      button.disabled = false;
    }
  }

  if (event.target.id === "report-form") {
    event.preventDefault();
    const year = new FormData(event.target).get("year");
    await loadReport(year);
  }
});

root.addEventListener("click", async event => {
  const edit = event.target.closest(".edit");
  const del = event.target.closest(".delete");
  const pdf = event.target.closest(".pdf");
  const cancel = event.target.closest("#cancel-edit");

  try {
    if (cancel) {
      await loadPage(current);
      return;
    }

    if (edit) {
      const resource = edit.dataset.resource;
      const id = edit.dataset.id;
      const rows = await api("/" + resource);
      const record = rows.find(row => String(row.id) === String(id));

      if (!record) throw new Error("Record not found.");

      const form = $("#record-form");
      if (!form) return;

      $("#record-id").value = record.id;
      $("#form-heading").textContent = "Edit record";
      $("#save-button").textContent = "Update record";
      $("#cancel-edit").classList.remove("hidden");

      fields[resource].forEach(field => {
        const input = form.elements[field.name];
        if (input) input.value = record[field.name] ?? "";
      });

      form.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }

    if (del) {
      if (!confirm("Are you sure you want to delete this record?")) return;

      await api("/" + del.dataset.resource + "/" + del.dataset.id, {
        method: "DELETE"
      });

      await loadPage(current);
      return;
    }

    if (pdf) {
      const response = await fetch(
        "/api/admin/invoices/" + pdf.dataset.id + "/pdf",
        { headers: { Authorization: "Bearer " + token } }
      );

      if (response.status === 401) {
        logout();
        throw new Error("Session expired. Please sign in again.");
      }

      if (!response.ok) {
        throw new Error("Could not generate invoice PDF.");
      }

      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const filename = match ? match[1] : "vireon-invoice.pdf";

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();

      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  } catch (error) {
    alert(error.message);
  }
});

// Restore existing session
if (token) {
  api("/summary")
    .then(() => showDashboard("Admin"))
    .catch(() => logout());
}
