
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const PDFDocument = require("pdfkit");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Set ADMIN_EMAIL and ADMIN_PASSWORD.");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("Set DATABASE_URL to your Supabase connection string.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000
});

pool.on("error", (err) => {
  console.error("Unexpected database pool error:", err.message);
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 180
}));

const currencies = ["USD", "INR", "EUR", "GBP"];

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS contacts (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      company TEXT DEFAULT '',
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS clients (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      company TEXT DEFAULT '',
      email TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS invoices (
      id BIGSERIAL PRIMARY KEY,
      invoice_no TEXT UNIQUE NOT NULL,
      client_name TEXT NOT NULL,
      issue_date DATE NOT NULL,
      due_date DATE,
      currency TEXT DEFAULT 'USD',
      amount NUMERIC(14,2) NOT NULL,
      status TEXT DEFAULT 'Pending',
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY,
      type TEXT NOT NULL CHECK(type IN ('Income','Expense')),
      entry_date DATE NOT NULL,
      category TEXT NOT NULL,
      description TEXT DEFAULT '',
      amount NUMERIC(14,2) NOT NULL,
      currency TEXT DEFAULT 'USD',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      details TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const existing = await pool.query(
    "SELECT id FROM admins WHERE lower(email) = $1",
    [ADMIN_EMAIL]
  );

  if (existing.rowCount === 0) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);

    await pool.query(
      "INSERT INTO admins(email, password_hash) VALUES($1, $2)",
      [ADMIN_EMAIL, hash]
    );

    console.log("Initial admin account created.");
  }

  console.log("Supabase database initialized.");
}

function clean(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}

function positiveAmount(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 && number < 1e12
    ? number
    : null;
}

function validDate(value, optional = false) {
  if (!value && optional) return true;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value || ""))) {
    return false;
  }

  const date = new Date(`${value}T00:00:00.000Z`);

  return !Number.isNaN(date.getTime()) &&
    date.toISOString().slice(0, 10) === value;
}

async function audit(action, details = "") {
  await pool.query(
    "INSERT INTO audit_logs(action, details) VALUES($1, $2)",
    [action, String(details).slice(0, 500)]
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.replace(/^Bearer\s+/i, "");

  try {
    if (!token) throw new Error("Missing token");

    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: "Authentication required. Please sign in again."
    });
  }
}

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

    if (!["Pending", "Paid", "Overdue"].includes(data.status)) {
      data.status = "Pending";
    }

    return null;
  }

  if (resource === "transactions") {
    if (!["Income", "Expense"].includes(data.type)) {
      return "Select Income or Expense.";
    }

    if (!validDate(data.entry_date)) {
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
  async (req, res) => {
    try {
      const name = clean(req.body.name, 120);
      const email = clean(req.body.email, 180).toLowerCase();
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

      await pool.query(
        `INSERT INTO contacts(name, email, company, message)
         VALUES($1, $2, $3, $4)`,
        [name, email, company, message]
      );

      res.json({
        ok: true,
        message: "Thank you. Your enquiry has been received."
      });
    } catch (err) {
      console.error("Contact submission error:", err.message);
      res.status(500).json({ error: "Unable to save your enquiry." });
    }
  }
);

// Admin login
app.post(
  "/api/admin/login",
  rateLimit({ windowMs: 15 * 60 * 1000, limit: 8 }),
  async (req, res) => {
    try {
      const email = clean(req.body.email, 180).toLowerCase();
      const password = String(req.body.password || "");

      const result = await pool.query(
        "SELECT * FROM admins WHERE lower(email) = $1",
        [email]
      );

      const admin = result.rows[0];

      if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
        return res.status(401).json({
          error: "Invalid email or password."
        });
      }

      const token = jwt.sign(
        { id: admin.id, email: admin.email },
        JWT_SECRET,
        { expiresIn: "8h" }
      );

      await audit("Admin login", email);

      res.json({ token, email: admin.email });
    } catch (err) {
      console.error("Login error:", err.message);
      res.status(500).json({ error: "Unable to sign in." });
    }
  }
);

// Dashboard summary
app.get("/api/admin/summary", auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COALESCE(SUM(amount) FILTER (WHERE type='Income'), 0) AS income,
        COALESCE(SUM(amount) FILTER (WHERE type='Expense'), 0) AS expenses
      FROM transactions
    `);

    const counts = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM clients) AS clients,
        (SELECT COUNT(*) FROM invoices) AS invoices,
        (SELECT COUNT(*) FROM invoices WHERE status != 'Paid') AS pending
    `);

    const currencyResult = await pool.query(`
      SELECT currency,
        COALESCE(SUM(amount) FILTER (WHERE type='Income'), 0) AS income,
        COALESCE(SUM(amount) FILTER (WHERE type='Expense'), 0) AS expenses
      FROM transactions
      GROUP BY currency
      ORDER BY currency
    `);

    const income = Number(result.rows[0].income);
    const expenses = Number(result.rows[0].expenses);

    res.json({
      income,
      expenses,
      profit: income - expenses,
      clients: Number(counts.rows[0].clients),
      invoices: Number(counts.rows[0].invoices),
      pending: Number(counts.rows[0].pending),
      currencyTotals: currencyResult.rows
    });
  } catch (err) {
    console.error("Summary error:", err.message);
    res.status(500).json({ error: "Unable to load dashboard summary." });
  }
});

// Monthly financial report
app.get("/api/admin/reports/monthly", auth, async (req, res) => {
  try {
    const year = Number(req.query.year || new Date().getFullYear());

    if (!Number.isInteger(year) || year < 2000 || year > 2100) {
      return res.status(400).json({ error: "Invalid report year." });
    }

    const result = await pool.query(`
      SELECT
        TO_CHAR(entry_date, 'YYYY-MM') AS month,
        currency,
        SUM(amount) FILTER (WHERE type='Income') AS income,
        SUM(amount) FILTER (WHERE type='Expense') AS expenses
      FROM transactions
      WHERE entry_date >= $1 AND entry_date < $2
      GROUP BY month, currency
      ORDER BY month, currency
    `, [`${year}-01-01`, `${year + 1}-01-01`]);

    res.json({ year, rows: result.rows });
  } catch (err) {
    console.error("Monthly report error:", err.message);
    res.status(500).json({ error: "Unable to load monthly report." });
  }
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
  app.get(`/api/admin/${resource}`, auth, async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT * FROM ${config.table} ORDER BY id DESC LIMIT 500`
      );

      res.json(result.rows);
    } catch (err) {
      console.error(`Load ${resource} error:`, err.message);
      res.status(500).json({ error: `Unable to load ${resource}.` });
    }
  });

  // Create record
  app.post(`/api/admin/${resource}`, auth, async (req, res) => {
    try {
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
      const values = columns.map(field => data[field]);
      const placeholders = columns.map((field, index) => `$${index + 1}`);

      const result = await pool.query(
        `INSERT INTO ${config.table} (${columns.join(",")})
         VALUES (${placeholders.join(",")})
         RETURNING id`,
        values
      );

      await audit(`Created ${resource}`, `ID ${result.rows[0].id}`);

      res.status(201).json({ id: result.rows[0].id });
    } catch (err) {
      console.error(`Create ${resource} error:`, err.message);
      res.status(400).json({
        error: "Could not save this record. Check required fields and unique values."
      });
    }
  });

  // Update record
  app.put(`/api/admin/${resource}/:id`, auth, async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ error: "Invalid record ID." });
      }

      const exists = await pool.query(
        `SELECT id FROM ${config.table} WHERE id = $1`,
        [id]
      );

      if (exists.rowCount === 0) {
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
      const values = columns.map(field => data[field]);

      const assignments = columns.map(
        (field, index) => `${field} = $${index + 1}`
      );

      values.push(id);

      await pool.query(
        `UPDATE ${config.table}
         SET ${assignments.join(", ")}
         WHERE id = $${values.length}`,
        values
      );

      await audit(`Updated ${resource}`, `ID ${id}`);

      res.json({ ok: true });
    } catch (err) {
      console.error(`Update ${resource} error:`, err.message);
      res.status(400).json({
        error: "Could not update this record. Check required fields and unique values."
      });
    }
  });
}

// Enquiries: view only
app.get("/api/admin/contacts", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM contacts ORDER BY id DESC LIMIT 500"
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Contacts error:", err.message);
    res.status(500).json({ error: "Unable to load enquiries." });
  }
});

// Activity logs: view only
app.get("/api/admin/logs", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200"
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Logs error:", err.message);
    res.status(500).json({ error: "Unable to load activity logs." });
  }
});

// Invoice PDF
app.get("/api/admin/invoices/:id/pdf", auth, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid invoice ID." });
    }

    const result = await pool.query(
      "SELECT * FROM invoices WHERE id = $1",
      [id]
    );

    const invoice = result.rows[0];

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
      .text(`Issue date: ${String(invoice.issue_date).slice(0, 10)}`)
      .text(`Due date: ${invoice.due_date ? String(invoice.due_date).slice(0, 10) : "—"}`)
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
  } catch (err) {
    console.error("Invoice PDF error:", err.message);

    if (!res.headersSent) {
      res.status(500).json({ error: "Unable to generate invoice PDF." });
    }
  }
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start only after the database is ready
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Vireon Group platform running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Database initialization failed:", err.message);
    process.exit(1);
  });

