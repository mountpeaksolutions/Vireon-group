require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const PDFDocument = require("pdfkit");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const { JWT_SECRET, ADMIN_PASSWORD, DATABASE_URL } = process.env;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();

if (!JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_EMAIL || !ADMIN_PASSWORD || !DATABASE_URL) {
  console.error("Set JWT_SECRET (32+ chars), ADMIN_EMAIL, ADMIN_PASSWORD and DATABASE_URL.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  connectionTimeoutMillis: 10000
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 180 }));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS contacts (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
      company TEXT DEFAULT '', message TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS clients (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, company TEXT DEFAULT '',
      email TEXT DEFAULT '', phone TEXT DEFAULT '', notes TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS invoices (
      id BIGSERIAL PRIMARY KEY, invoice_no TEXT UNIQUE NOT NULL, client_name TEXT NOT NULL,
      issue_date DATE NOT NULL, due_date DATE, currency TEXT DEFAULT 'USD',
      amount NUMERIC(14,2) NOT NULL, status TEXT DEFAULT 'Pending',
      description TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY, type TEXT NOT NULL CHECK(type IN ('Income','Expense')),
      entry_date DATE NOT NULL, category TEXT NOT NULL, description TEXT DEFAULT '',
      amount NUMERIC(14,2) NOT NULL, currency TEXT DEFAULT 'USD',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL, details TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  const found = await pool.query("SELECT id FROM admins WHERE lower(email)=$1", [ADMIN_EMAIL]);
  if (!found.rowCount) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query("INSERT INTO admins(email,password_hash) VALUES($1,$2)", [ADMIN_EMAIL, hash]);
  }
}

const clean = (v, n=500) => String(v ?? "").trim().slice(0,n);
const currencies = ["USD","INR","EUR","GBP"];
const validDate = (v, optional=false) => {
  if (!v && optional) return true;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(v || ""))) return false;
  const d = new Date(`${v}T00:00:00.000Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0,10) === v;
};
const positiveAmount = v => {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n < 1e12 ? n : null;
};
async function audit(action, details="") {
  await pool.query("INSERT INTO audit_logs(action,details) VALUES($1,$2)", [action,String(details).slice(0,500)]);
}
function auth(req,res,next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i,"");
    if (!token) throw new Error("No token");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({error:"Authentication required. Please sign in again."});
  }
}
function validate(resource,d,raw) {
  if (resource === "clients") return d.name ? null : "Client name is required.";
  if (resource === "invoices") {
    if (!d.invoice_no || !d.client_name || !d.issue_date) return "Invoice number, client name and issue date are required.";
    if (!validDate(d.issue_date) || !validDate(d.due_date,true)) return "Enter valid invoice dates.";
    d.amount = positiveAmount(raw.amount);
    if (!d.amount) return "Enter a valid positive amount.";
    if (!currencies.includes(d.currency)) d.currency="USD";
    if (!["Pending","Paid","Overdue"].includes(d.status)) d.status="Pending";
    return null;
  }
  if (resource === "transactions") {
    if (!["Income","Expense"].includes(d.type)) return "Select Income or Expense.";
    if (!validDate(d.entry_date)) return "Enter a valid transaction date.";
    if (!d.category) return "Category is required.";
    d.amount=positiveAmount(raw.amount);
    if (!d.amount) return "Enter a valid positive amount.";
    if (!currencies.includes(d.currency)) d.currency="USD";
    return null;
  }
  return "Invalid resource.";
}

app.post("/api/contact", rateLimit({windowMs:3600000,limit:8}), async (req,res,next)=>{
  try {
    const d={name:clean(req.body.name,120),email:clean(req.body.email,180),company:clean(req.body.company,160),message:clean(req.body.message,3000)};
    if (!d.name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email) || d.message.length<8)
      return res.status(400).json({error:"Please provide a name, valid email and message."});
    await pool.query("INSERT INTO contacts(name,email,company,message) VALUES($1,$2,$3,$4)",[d.name,d.email,d.company,d.message]);
    res.json({ok:true,message:"Thank you. Your enquiry has been received."});
  } catch(e){next(e);}
});

app.post("/api/admin/login", rateLimit({windowMs:900000,limit:8}), async (req,res,next)=>{
  try {
    const email=clean(req.body.email,180).toLowerCase(), password=String(req.body.password||"");
    const q=await pool.query("SELECT * FROM admins WHERE lower(email)=$1",[email]);
    const admin=q.rows[0];
    if (!admin || !(await bcrypt.compare(password,admin.password_hash)))
      return res.status(401).json({error:"Invalid email or password."});
    const token=jwt.sign({id:admin.id,email:admin.email},JWT_SECRET,{expiresIn:"8h"});
    await audit("Admin login",email);
    res.json({token,email:admin.email});
  } catch(e){next(e);}
});

app.get("/api/admin/summary",auth,async(req,res,next)=>{
  try {
    const [totals,counts]=await Promise.all([
      pool.query(`SELECT currency,
        COALESCE(SUM(CASE WHEN type='Income' THEN amount ELSE 0 END),0) income,
        COALESCE(SUM(CASE WHEN type='Expense' THEN amount ELSE 0 END),0) expenses
        FROM transactions GROUP BY currency ORDER BY currency`),
      pool.query(`SELECT (SELECT COUNT(*) FROM clients)::int clients,
        (SELECT COUNT(*) FROM invoices)::int invoices,
        (SELECT COUNT(*) FROM invoices WHERE status<>'Paid')::int pending`)
    ]);
    const currencyTotals=totals.rows.map(r=>({currency:r.currency,income:Number(r.income),expenses:Number(r.expenses)}));
    const income=currencyTotals.reduce((s,r)=>s+r.income,0), expenses=currencyTotals.reduce((s,r)=>s+r.expenses,0);
    res.json({income,expenses,profit:income-expenses,...counts.rows[0],currencyTotals});
  } catch(e){next(e);}
});

app.get("/api/admin/reports/monthly",auth,async(req,res,next)=>{
  try {
    const year=Number(req.query.year||new Date().getFullYear());
    if(!Number.isInteger(year)||year<2000||year>2100) return res.status(400).json({error:"Invalid report year."});
    const q=await pool.query(`SELECT TO_CHAR(entry_date,'YYYY-MM') month,currency,
      SUM(CASE WHEN type='Income' THEN amount ELSE 0 END) income,
      SUM(CASE WHEN type='Expense' THEN amount ELSE 0 END) expenses
      FROM transactions WHERE entry_date >= $1::date AND entry_date < $2::date
      GROUP BY month,currency ORDER BY month,currency`,[`${year}-01-01`,`${year+1}-01-01`]);
    res.json({year,rows:q.rows.map(r=>({...r,income:Number(r.income),expenses:Number(r.expenses)}))});
  } catch(e){next(e);}
});

const resources={
  clients:{table:"clients",fields:["name","company","email","phone","notes"]},
  invoices:{table:"invoices",fields:["invoice_no","client_name","issue_date","due_date","currency","amount","status","description"]},
  transactions:{table:"transactions",fields:["type","entry_date","category","description","amount","currency"]}
};

for(const [resource,cfg] of Object.entries(resources)){
  app.get(`/api/admin/${resource}`,auth,async(req,res,next)=>{
    try{const q=await pool.query(`SELECT * FROM ${cfg.table} ORDER BY id DESC LIMIT 500`);res.json(q.rows);}catch(e){next(e);}
  });
  app.post(`/api/admin/${resource}`,auth,async(req,res,next)=>{
    try{
      const d={}; for(const f of cfg.fields)d[f]=clean(req.body[f],f==="notes"||f==="description"?2000:180);
      const error=validate(resource,d,req.body);if(error)return res.status(400).json({error});
      const fields=Object.keys(d), vals=fields.map(f=>d[f]), marks=fields.map((_,i)=>`$${i+1}`);
      const q=await pool.query(`INSERT INTO ${cfg.table}(${fields.join(",")}) VALUES(${marks.join(",")}) RETURNING id`,vals);
      await audit(`Created ${resource}`,`ID ${q.rows[0].id}`);res.status(201).json({id:q.rows[0].id});
    }catch(e){if(e.code==="23505")return res.status(400).json({error:"That invoice number already exists."});next(e);}
  });
  app.put(`/api/admin/${resource}/:id`,auth,async(req,res,next)=>{
    try{
      const id=Number(req.params.id);if(!Number.isInteger(id)||id<1)return res.status(400).json({error:"Invalid record ID."});
      const d={};for(const f of cfg.fields)d[f]=clean(req.body[f],f==="notes"||f==="description"?2000:180);
      const error=validate(resource,d,req.body);if(error)return res.status(400).json({error});
      const fields=Object.keys(d),vals=fields.map(f=>d[f]);vals.push(id);
      const sets=fields.map((f,i)=>`${f}=$${i+1}`);
      const q=await pool.query(`UPDATE ${cfg.table} SET ${sets.join(",")} WHERE id=$${vals.length} RETURNING id`,vals);
      if(!q.rowCount)return res.status(404).json({error:"Record not found."});
      await audit(`Updated ${resource}`,`ID ${id}`);res.json({ok:true});
    }catch(e){if(e.code==="23505")return res.status(400).json({error:"That invoice number already exists."});next(e);}
  });
  app.delete(`/api/admin/${resource}/:id`,auth,async(req,res,next)=>{
    try{
      const id=Number(req.params.id);if(!Number.isInteger(id)||id<1)return res.status(400).json({error:"Invalid record ID."});
      const q=await pool.query(`DELETE FROM ${cfg.table} WHERE id=$1 RETURNING id`,[id]);
      if(!q.rowCount)return res.status(404).json({error:"Record not found."});
      await audit(`Deleted ${resource}`,`ID ${id}`);res.json({ok:true});
    }catch(e){next(e);}
  });
}

app.get("/api/admin/contacts",auth,async(req,res,next)=>{
  try{const q=await pool.query("SELECT * FROM contacts ORDER BY id DESC LIMIT 500");res.json(q.rows);}catch(e){next(e);}
});
app.get("/api/admin/logs",auth,async(req,res,next)=>{
  try{const q=await pool.query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200");res.json(q.rows);}catch(e){next(e);}
});
app.get("/api/admin/invoices/:id/pdf",auth,async(req,res,next)=>{
  try{
    const id=Number(req.params.id);if(!Number.isInteger(id)||id<1)return res.status(400).json({error:"Invalid invoice ID."});
    const q=await pool.query("SELECT * FROM invoices WHERE id=$1",[id]), inv=q.rows[0];
    if(!inv)return res.status(404).json({error:"Invoice not found."});
    const filename=inv.invoice_no.replace(/[^a-zA-Z0-9_-]/g,"")||"invoice";
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition",`attachment; filename="${filename}.pdf"`);
    const doc=new PDFDocument({margin:54});doc.pipe(res);
    doc.fillColor("#9b6716").fontSize(25).text("VIREON GROUP").moveDown();
    doc.fillColor("#38291f").fontSize(20).text("INVOICE").moveDown();
    doc.fontSize(11).text(`Invoice: ${inv.invoice_no}`)
      .text(`Issue date: ${String(inv.issue_date).slice(0,10)}`)
      .text(`Due date: ${inv.due_date?String(inv.due_date).slice(0,10):"—"}`)
      .moveDown().text(`Bill to: ${inv.client_name}`)
      .text(`Description: ${inv.description||"Professional services"}`)
      .moveDown().fontSize(16).text(`Total: ${inv.currency} ${Number(inv.amount).toFixed(2)}`)
      .fontSize(11).text(`Status: ${inv.status}`).moveDown(3);
    doc.fillColor("#9b6716").text("Thank you for your business.");doc.end();
  }catch(e){next(e);}
});

app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,req,res,next)=>{
  console.error("Server error:",err);
  if(res.headersSent)return next(err);
  res.status(500).json({error:"An unexpected server error occurred."});
});

initDb().then(()=>app.listen(PORT,()=>console.log(`Vireon Group running on ${PORT}`)))
  .catch(err=>{console.error("Database initialization failed:",err);process.exit(1);});

