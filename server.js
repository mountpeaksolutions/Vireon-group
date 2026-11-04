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
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random value of at least 32 characters.");
  process.exit(1);
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
  console.error("Set ADMIN_EMAIL and ADMIN_PASSWORD in .env before starting.");
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
 id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
 company TEXT DEFAULT '', message TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS clients (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, company TEXT DEFAULT '',
 email TEXT DEFAULT '', phone TEXT DEFAULT '', notes TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS invoices (
 id INTEGER PRIMARY KEY, invoice_no TEXT UNIQUE NOT NULL, client_name TEXT NOT NULL,
 issue_date TEXT NOT NULL, due_date TEXT DEFAULT '', currency TEXT DEFAULT 'USD',
 amount REAL NOT NULL, status TEXT DEFAULT 'Pending', description TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
 id INTEGER PRIMARY KEY, type TEXT NOT NULL CHECK(type IN ('Income','Expense')),
 entry_date TEXT NOT NULL, category TEXT NOT NULL, description TEXT DEFAULT '',
 amount REAL NOT NULL, currency TEXT DEFAULT 'USD',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY, action TEXT NOT NULL, details TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const admin = db.prepare("SELECT id FROM admins WHERE email=?").get(process.env.ADMIN_EMAIL);
if (!admin) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO admins(email,password_hash) VALUES(?,?)").run(process.env.ADMIN_EMAIL, hash);
}

function audit(action, details = "") {
  db.prepare("INSERT INTO audit_logs(action,details) VALUES(?,?)").run(action, String(details).slice(0, 500));
}
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    if (!token) throw new Error("missing");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Authentication required." });
  }
}
function clean(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}
function positiveAmount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 && n < 1e12 ? n : null;
}

app.post("/api/contact", rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }), (req, res) => {
  const name = clean(req.body.name, 120), email = clean(req.body.email, 180);
  const company = clean(req.body.company, 160), message = clean(req.body.message, 3000);
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || message.length < 8) {
    return res.status(400).json({ error: "Please provide a name, valid email and message." });
  }
  db.prepare("INSERT INTO contacts(name,email,company,message) VALUES(?,?,?,?)")
    .run(name, email, company, message);
  res.json({ ok: true, message: "Thank you. Your enquiry has been received." });
});

app.post("/api/admin/login", rateLimit({ windowMs: 15 * 60 * 1000, limit: 8 }), (req, res) => {
  const email = clean(req.body.email, 180).toLowerCase();
  const row = db.prepare("SELECT * FROM admins WHERE email=?").get(email);
  if (!row || !bcrypt.compareSync(String(req.body.password || ""), row.password_hash)) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  const token = jwt.sign({ id: row.id, email: row.email }, JWT_SECRET, { expiresIn: "8h" });
  audit("Admin login", email);
  res.json({ token, email });
});

app.get("/api/admin/summary", auth, (req, res) => {
  const income = db.prepare("SELECT COALESCE(SUM(amount),0) n FROM transactions WHERE type='Income'").get().n;
  const expenses = db.prepare("SELECT COALESCE(SUM(amount),0) n FROM transactions WHERE type='Expense'").get().n;
  const clients = db.prepare("SELECT COUNT(*) n FROM clients").get().n;
  const invoices = db.prepare("SELECT COUNT(*) n FROM invoices").get().n;
  const pending = db.prepare("SELECT COUNT(*) n FROM invoices WHERE status!='Paid'").get().n;
  res.json({ income, expenses, profit: income-expenses, clients, invoices, pending });
});

const resources = {
  clients: { table: "clients", fields: ["name","company","email","phone","notes"], required: ["name"] },
  invoices: { table: "invoices", fields: ["invoice_no","client_name","issue_date","due_date","currency","amount","status","description"], required: ["invoice_no","client_name","issue_date","amount"] },
  transactions: { table: "transactions", fields: ["type","entry_date","category","description","amount","currency"], required: ["type","entry_date","category","amount"] }
};
for (const [resource, config] of Object.entries(resources)) {
  app.get(`/api/admin/${resource}`, auth, (req, res) => {
    res.json(db.prepare(`SELECT * FROM ${config.table} ORDER BY id DESC LIMIT 500`).all());
  });
  app.post(`/api/admin/${resource}`, auth, (req, res) => {
    const data = {};
    for (const f of config.fields) data[f] = clean(req.body[f], f === "description" || f === "notes" ? 2000 : 180);
    for (const f of config.required) if (!data[f]) return res.status(400).json({ error: `${f} is required.` });
    if (config.fields.includes("amount")) {
      const amount = positiveAmount(req.body.amount);
      if (!amount) return res.status(400).json({ error: "Enter a valid positive amount." });
      data.amount = amount;
    }
    if (resource === "transactions" && !["Income","Expense"].includes(data.type)) return res.status(400).json({ error: "Invalid transaction type." });
    if (resource === "invoices" && !["USD","INR","EUR","GBP"].includes(data.currency)) data.currency = "USD";
    if (resource === "invoices" && !["Pending","Paid","Overdue"].includes(data.status)) data.status = "Pending";
    const cols = Object.keys(data);
    try {
      const result = db.prepare(`INSERT INTO ${config.table} (${cols.join(",")}) VALUES (${cols.map(()=>"?").join(",")})`).run(...cols.map(k=>data[k]));
      audit(`Created ${resource}`, `ID ${result.lastInsertRowid}`);
      res.status(201).json({ id: result.lastInsertRowid });
    } catch {
      res.status(400).json({ error: "Could not save this record. Check required fields and unique values." });
    }
  });
  app.delete(`/api/admin/${resource}/:id`, auth, (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: "Invalid record ID." });
    const result = db.prepare(`DELETE FROM ${config.table} WHERE id=?`).run(id);
    if (!result.changes) return res.status(404).json({ error: "Record not found." });
    audit(`Deleted ${resource}`, `ID ${id}`);
    res.json({ ok: true });
  });
}
app.get("/api/admin/contacts", auth, (req,res)=>res.json(db.prepare("SELECT * FROM contacts ORDER BY id DESC LIMIT 500").all()));
app.get("/api/admin/logs", auth, (req,res)=>res.json(db.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").all()));

app.get("/api/admin/invoices/:id/pdf", auth, (req,res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id=?").get(Number(req.params.id));
  if (!invoice) return res.status(404).json({ error: "Invoice not found." });
  res.setHeader("Content-Type","application/pdf");
  res.setHeader("Content-Disposition",`attachment; filename="${invoice.invoice_no.replace(/[^a-zA-Z0-9_-]/g,"")}.pdf"`);
  const doc = new PDFDocument({ margin: 54 });
  doc.pipe(res);
  doc.fillColor("#9b6716").fontSize(25).text("VIREON GROUP");
  doc.moveDown().fillColor("#38291f").fontSize(20).text("INVOICE");
  doc.moveDown().fontSize(11).text(`Invoice: ${invoice.invoice_no}`)
    .text(`Issue date: ${invoice.issue_date}`).text(`Due date: ${invoice.due_date || "—"}`)
    .moveDown().text(`Bill to: ${invoice.client_name}`).text(`Description: ${invoice.description || "Professional services"}`)
    .moveDown().fontSize(16).text(`Total: ${invoice.currency} ${Number(invoice.amount).toFixed(2)}`)
    .fontSize(11).text(`Status: ${invoice.status}`);
  doc.moveDown(3).fillColor("#9b6716").text("Thank you for your business.");
  doc.end();
});

app.get("/admin", (req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("*", (req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT, ()=>console.log(`Vireon Group platform running on port ${PORT}`));
