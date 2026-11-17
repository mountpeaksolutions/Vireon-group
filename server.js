
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const PDFDocument = require("pdfkit");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Set ADMIN_EMAIL and ADMIN_PASSWORD in environment variables.");
  process.exit(1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 180 }));

const db = new Database(path.join(__dirname, "vireon.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
 id INTEGER PRIMARY KEY,
 name TEXT NOT NULL,
 email TEXT NOT NULL,
 company TEXT DEFAULT '',
 message TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clients (
 id INTEGER PRIMARY KEY,
 name TEXT NOT NULL,
 company TEXT DEFAULT '',
 email TEXT DEFAULT '',
 phone TEXT DEFAULT '',
 notes TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS invoices (
 id INTEGER PRIMARY KEY,
 invoice_no TEXT UNIQUE NOT NULL,
 client_name TEXT NOT NULL,
 issue_date TEXT NOT NULL,
 due_date TEXT DEFAULT '',
 currency TEXT DEFAULT 'USD',
 amount REAL NOT NULL,
 status TEXT DEFAULT 'Pending',
 description TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
 id INTEGER PRIMARY KEY,
 type TEXT NOT NULL CHECK(type IN ('Income','Expense')),
 entry_date TEXT NOT NULL,
 category TEXT NOT NULL,
 description TEXT DEFAULT '',
 amount REAL NOT NULL,
 currency TEXT DEFAULT 'USD',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY,
 action TEXT NOT NULL,
 details TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// Create the initial admin only if no matching email exists.
const existingAdmin = db.prepare(
  "SELECT id FROM admins WHERE lower(email) = ?"
).get(ADMIN_EMAIL);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare(
    "INSERT INTO admins(email, password_hash) VALUES(?, ?)"
  ).run(ADMIN_EMAIL, hash);
}

function audit(action, details = "") {
  db.prepare(
    "INSERT INTO audit_logs(action, details) VALUES(?, ?)"
  ).run(action, String(details).slice(0, 500));
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace(/^Bearer\s+/i, "");

  try {
    if (!token) throw new Error("Missing token");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Authentication required. Please sign in again." });
  }
}

function clean(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}

function positiveAmount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 && n < 1e12 ? n : null;
}

function validDate(value, optional = false) {
  if (!value && optional) return true;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.getTime()) &&
    date.toISOString().slice(0, 10) === value;
}

const currencies = ["USD", "INR", "EUR", "GBP"];

function validateRecord(resource, data, raw) {
  if (resource === "clients") {
    if (!data.name) return "Client name is required.";
    return null;
  }

  if (resource === "invoices") {
    if (!data.invoice_no || !data.client_name || !data.issue_date) {
      return "Invoice number, client name and issue date are required.";
    }
    if (!validDate(data.issue_date) || !validDate(data.due_date, true)) {
      return "Enter valid invoice dates.";
    }
    data.amount = positiveAmount(raw.amount);
    if (!data.amount) return "Enter a valid positive amount.";
    if (!currencies.includes(data.currency)) data.currency = "USD";
    if (!["Pending", "Paid", "Overdue"].includes(data.status)) data.status = "Pending";
    return null;
  }

  if (resource === "transactions") {
    if (!["Income", "Expense"].includes(data.type)) {
      return "Select Income or Expense.";
    }
    if (!data.entry_date || !validDate(data.entry_date)) {
      return "Enter a valid transaction date.";
    }
    if (!data.category) return "Category is required.";
    data.amount = positiveAmount(raw.amount);
    if (!data.amount) return "Enter a valid positive amount.";
    if (!currencies.includes(data.currency)) data.currency = "USD";
    return null;
  }

  return "Invalid resource.";
}

// Public contact form
app.post(
  "/api/contact",
  rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }),
  (req, res) => {
    const name = clean(req.body.name, 120);
    const email = clean(req.body.email, 180);
    const company = clean(req.body.company, 160);
    const message = clean(req.body.message, 3000);

    if (
      !name ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      message.length < 8
    ) {
      return res.status(400).json({
        error: "Please provide a name, valid email and message."
      });
    }

    db.prepare(
      "INSERT INTO contacts(name, email, company, message) VALUES(?, ?, ?, ?)"
    ).run(name, email, company, message);

    res.json({
      ok: true,
      message: "Thank you. Your enquiry has been received."
    });
  }
);

// Admin login
app.post(
  "/api/admin/login",
  rateLimit({ windowMs: 15 * 60 * 1000, limit: 8 }),
  (req, res) => {
    const email = clean(req.body.email, 180).toLowerCase();
    const password = String(req.body.password || "");

    const row = db.prepare(
      "SELECT * FROM admins WHERE lower(email) = ?"
    ).get(email);

    if (!row || !bcrypt.compareSync(password, row.password_hash)) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const token = jwt.sign(
      { id: row.id, email: row.email },
      JWT_SECRET,
      { expiresIn: "8h" }
    );

    audit("Admin login", email);
    res.json({ token, email: row.email });
  }
);

// Dashboard summary
app.get("/api/admin/summary", auth, (req, res) => {
  const income = db.prepare(
    "SELECT COALESCE(SUM(amount), 0) n FROM transactions WHERE type='Income'"
  ).get().n;

  const expenses = db.prepare(
    "SELECT COALESCE(SUM(amount), 0) n FROM transactions WHERE type='Expense'"
  ).get().n;

  const clients = db.prepare(
    "SELECT COUNT(*) n FROM clients"
  ).get().n;

  const invoices = db.prepare(
    "SELECT COUNT(*) n FROM invoices"
  ).get().n;

  const pending = db.prepare(
    "SELECT COUNT(*) n FROM invoices WHERE status != 'Paid'"
  ).get().n;

  const currencyTotals = db.prepare(`
    SELECT currency,
      SUM(CASE WHEN type='Income' THEN amount ELSE 0 END) AS income,
      SUM(CASE WHEN type='Expense' THEN amount ELSE 0 END) AS expenses
    FROM transactions
    GROUP BY currency
    ORDER BY currency
  `).all();

  res.json({
    income,
    expenses,
    profit: income - expenses,
    clients,
    invoices,
    pending,
    currencyTotals
  });
});

// Monthly financial report.
// Amounts remain separated by currency; no exchange conversion is assumed.
app.get("/api/admin/reports/monthly", auth, (req, res) => {
  const year = Number(req.query.year || new Date().getFullYear());

  if (!Number.isInteger(year) || year < 2000 || year > 2100) {
    return res.status(400).json({ error: "Invalid report year." });
  }

  const rows = db.prepare(`
    SELECT
      substr(entry_date, 1, 7) AS month,
      currency,
      SUM(CASE WHEN type='Income' THEN amount ELSE 0 END) AS income,
      SUM(CASE WHEN type='Expense' THEN amount ELSE 0 END) AS expenses
    FROM transactions
    WHERE entry_date >= ? AND entry_date < ?
    GROUP BY month, currency
    ORDER BY month, currency
  `).all(`${year}-01-01`, `${year + 1}-01-01`);

  res.json({ year, rows });
});

// Resource management
const resources = {
  clients: {
    table: "clients",
    fields: ["name", "company", "email", "phone", "notes"]
  },
  invoices: {
    table: "invoices",
    fields: [
      "invoice_no", "client_name", "issue_date", "due_date",
      "currency", "amount", "status", "description"
    ]
  },
  transactions: {
    table: "transactions",
    fields: [
      "type", "entry_date", "category", "description", "amount", "currency"
    ]
  }
};

for (const [resource, config] of Object.entries(resources)) {
  app.get(`/api/admin/${resource}`, auth, (req, res) => {
    const rows = db.prepare(
      `SELECT * FROM ${config.table} ORDER BY id DESC LIMIT 500`
    ).all();

    res.json(rows);
  });

  // Create
  app.post(`/api/admin/${resource}`, auth, (req, res) => {
    const data = {};

    for (const field of config.fields) {
      data[field] = clean(
        req.body[field],
        field === "description" || field === "notes" ? 2000 : 180
      );
    }

    const error = validateRecord(resource, data, req.body);
    if (error) return res.status(400).json({ error });

    const columns = Object.keys(data);

    try {
      const result = db.prepare(
        `INSERT INTO ${config.table}
         (${columns.join(",")})
         VALUES (${columns.map(() => "?").join(",")})`
      ).run(...columns.map(key => data[key]));

      audit(`Created ${resource}`, `ID ${result.lastInsertRowid}`);
      res.status(201).json({ id: result.lastInsertRowid });
    } catch {
      res.status(400).json({
        error: "Could not save this record. Check required fields and unique values."
      });
    }
  });

  // Update
  app.put(`/api/admin/${resource}/:id`, auth, (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid record ID." });
    }

    const exists = db.prepare(
      `SELECT id FROM ${config.table} WHERE id = ?`
    ).get(id);

    if (!exists) {
      return res.status(404).json({ error: "Record not found." });
    }

    const data = {};

    for (const field of config.fields) {
      data[field] = clean(
        req.body[field],
        field === "description" || field === "notes" ? 2000 : 180
      );
    }

    const error = validateRecord(resource, data, req.body);
    if (error) return res.status(400).json({ error });

    const columns = Object.keys(data);
    const assignments = columns.map(key => `${key} = ?`).join(", ");

    try {
      db.prepare(
        `UPDATE ${config.table} SET ${assignments} WHERE id = ?`
      ).run(...columns.map(key => data[key]), id);

      audit(`Updated ${resource}`, `ID ${id}`);
      res.json({ ok: true });
    } catch {
      res.status(400).json({
        error: "Could not update this record. Check required fields and unique values."
      });
    }
  });

  // Delete
  app.delete(`/api/admin/${resource}/:id`, auth, (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid record ID." });
    }

    const result = db.prepare(
      `DELETE FROM ${config.table} WHERE id = ?`
    ).run(id);

    if (!result.changes) {
      return res.status(404).json({ error: "Record not found." });
    }

    audit(`Deleted ${resource}`, `ID ${id}`);
    res.json({ ok: true });
  });
}

// Enquiries: view only
app.get("/api/admin/contacts", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM contacts ORDER BY id DESC LIMIT 500").all()
  );
});

// Activity logs: view only
app.get("/api/admin/logs", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").all()
  );
});

// Invoice PDF
app.get("/api/admin/invoices/:id/pdf", auth, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid invoice ID." });
  }

  const invoice = db.prepare(
    "SELECT * FROM invoices WHERE id = ?"
  ).get(id);

  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found." });
  }

  const safeName = invoice.invoice_no.replace(/[^a-zA-Z0-9_-]/g, "");

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${safeName || "invoice"}.pdf"`
  );

  const doc = new PDFDocument({ margin: 54 });
  doc.pipe(res);

  doc.fillColor("#9b6716").fontSize(25).text("VIREON GROUP");
  doc.moveDown();
  doc.fillColor("#38291f").fontSize(20).text("INVOICE");
  doc.moveDown();
  doc.fontSize(11)
    .text(`Invoice: ${invoice.invoice_no}`)
    .text(`Issue date: ${invoice.issue_date}`)
    .text(`Due date: ${invoice.due_date || "—"}`)
    .moveDown()
    .text(`Bill to: ${invoice.client_name}`)
    .text(`Description: ${invoice.description || "Professional services"}`)
    .moveDown()
    .fontSize(16)
    .text(`Total: ${invoice.currency} ${Number(invoice.amount).toFixed(2)}`)
    .fontSize(11)
    .text(`Status: ${invoice.status}`);

  doc.moveDown(3);
  doc.fillColor("#9b6716").text("Thank you for your business.");
  doc.end();
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Vireon Group platform running on port ${PORT}`);
});
