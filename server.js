require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, {recursive:true});
const db = new sqlite3.Database(path.join(DATA_DIR, 'oneshi.sqlite'));
const run = (sql, params=[]) => new Promise((resolve,reject)=>db.run(sql,params,function(e){e?reject(e):resolve(this)}));
const get = (sql, params=[]) => new Promise((resolve,reject)=>db.get(sql,params,(e,r)=>e?reject(e):resolve(r)));
const all = (sql, params=[]) => new Promise((resolve,reject)=>db.all(sql,params,(e,r)=>e?reject(e):resolve(r)));

async function init(){
 await run(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, father_name TEXT NOT NULL, branch TEXT NOT NULL, relationship TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, payment_reference TEXT, payment_note TEXT, role TEXT NOT NULL DEFAULT 'member', status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, approved_at TEXT)`);
 await run(`CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,body TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,created_by INTEGER)`);
 const email=(process.env.ADMIN_EMAIL||'admin@example.com').toLowerCase();
 const exists=await get('SELECT id,role FROM users WHERE email=?',[email]);
 const hash=await bcrypt.hash(process.env.ADMIN_PASSWORD||'ChangeThisToALongUniquePassword123!',12);
 if(!exists){
   await run('INSERT INTO users(full_name,father_name,branch,relationship,phone,email,password_hash,role,status,approved_at) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)',[process.env.ADMIN_NAME||'Family Administrator','N/A','Administrator','Family administrator','N/A',email,hash,'admin','approved']);
 } else {
   // Ensure the configured administrator can sign in even if this database was initialized earlier.
   await run('UPDATE users SET full_name=?,password_hash=?,role=?,status=?,approved_at=COALESCE(approved_at,CURRENT_TIMESTAMP) WHERE id=?',[process.env.ADMIN_NAME||'Family Administrator',hash,'admin','approved',exists.id]);
 }
}
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],scriptSrc:["'self'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],upgradeInsecureRequests:null}}}));
app.use(express.urlencoded({extended:false,limit:'20kb'}));
app.use(express.json({limit:'20kb'}));
app.use(session({store:new SQLiteStore({db:'sessions.sqlite',dir:DATA_DIR}),secret:process.env.SESSION_SECRET||'development-only-change-this-secret',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',maxAge:1000*60*60*8}}));
app.use(express.static(path.join(ROOT,'public')));
app.get('/admin',(req,res)=>res.sendFile(path.join(ROOT,'public','admin.html')));
app.use('/api/',rateLimit({windowMs:15*60*1000,limit:100,standardHeaders:true,legacyHeaders:false}));
const auth=(req,res,next)=>req.session.user?next():res.status(401).json({error:'Please log in.'});
const approved=(req,res,next)=>{if(!req.session.user)return res.status(401).json({error:'Please log in.'});if(req.session.user.status!=='approved')return res.status(403).json({error:'Your membership is awaiting approval.'});next()};
const admin=(req,res,next)=>{if(!req.session.user)return res.status(401).json({error:'Please log in.'});if(req.session.user.role!=='admin')return res.status(403).json({error:'Administrator access required.'});next()};
function safeUser(u){return {id:u.id,fullName:u.full_name,email:u.email,role:u.role,status:u.status,branch:u.branch,relationship:u.relationship};}
app.get('/api/me',async(req,res)=>{if(!req.session.user)return res.json({user:null});const u=await get('SELECT * FROM users WHERE id=?',[req.session.user.id]);if(!u){req.session.destroy(()=>{});return res.json({user:null})}req.session.user={id:u.id,role:u.role,status:u.status};res.json({user:safeUser(u)});});
app.post('/api/register',async(req,res)=>{try{
 const {fullName,fatherName,branch,relationship,phone,email,password,paymentReference,paymentNote}=req.body;
 for(const [v,label] of [[fullName,'Full name'],[fatherName,"Father's name"],[branch,'Family branch'],[relationship,'Relationship'],[phone,'Phone number'],[email,'Email'],[password,'Password']]) if(typeof v!=='string'||!v.trim())return res.status(400).json({error:`${label} is required.`});
 if(!/^\S+@\S+\.\S+$/.test(email.trim()))return res.status(400).json({error:'Enter a valid email address.'});
 if(password.length<10)return res.status(400).json({error:'Password must be at least 10 characters.'});
 if(!paymentReference||!String(paymentReference).trim())return res.status(400).json({error:'Enter a payment reference or write “Recognized family member — no fee” if the family already recognizes you.'});
 const hash=await bcrypt.hash(password,12);
 await run('INSERT INTO users(full_name,father_name,branch,relationship,phone,email,password_hash,payment_reference,payment_note,status) VALUES(?,?,?,?,?,?,?,?,?,?)',[fullName.trim(),fatherName.trim(),branch.trim(),relationship.trim(),phone.trim(),email.trim().toLowerCase(),hash,String(paymentReference).trim(),String(paymentNote||'').trim(),'pending']);
 res.status(201).json({message:'Application received. An administrator will review your family details and payment before granting access.'});
 }catch(e){if(String(e.message).includes('UNIQUE'))return res.status(409).json({error:'An application or account already exists for that email.'});console.error(e);res.status(500).json({error:'Could not submit application.'})}});
app.post('/api/login',async(req,res)=>{try{const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');const u=await get('SELECT * FROM users WHERE email=?',[email]);if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:'Email or password is incorrect.'});if(u.status==='rejected'||u.status==='suspended')return res.status(403).json({error:'This account does not currently have access. Contact the family administrator.'});req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not start secure session.'});req.session.user={id:u.id,role:u.role,status:u.status};res.json({user:safeUser(u),message:u.status==='pending'?'You are logged in, but family access is pending approval.':''})})}catch(e){console.error(e);res.status(500).json({error:'Could not log in.'})}});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('connect.sid');res.json({message:'Logged out.'})}));
app.get('/api/tree',approved,async(req,res)=>{try{res.json(JSON.parse(fs.readFileSync(path.join(DATA_DIR,'family-tree.json'),'utf8')))}catch(e){res.status(500).json({error:'Family tree is unavailable.'})}});
app.get('/api/profile',approved,async(req,res)=>{const u=await get('SELECT id,full_name,father_name,branch,relationship,phone,email,status,created_at FROM users WHERE id=?',[req.session.user.id]);res.json(u)});
app.get('/api/announcements',approved,async(req,res)=>res.json(await all('SELECT id,title,body,created_at FROM announcements ORDER BY id DESC LIMIT 100')));
app.get('/api/admin/applications',admin,async(req,res)=>res.json(await all("SELECT id,full_name,father_name,branch,relationship,phone,email,payment_reference,payment_note,status,created_at FROM users WHERE role!='admin' ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END,created_at DESC")));
app.post('/api/admin/applications/:id/status',admin,async(req,res)=>{const status=String(req.body.status||'');if(!['approved','rejected','suspended','pending'].includes(status))return res.status(400).json({error:'Invalid status.'});const u=await get('SELECT id,role FROM users WHERE id=?',[req.params.id]);if(!u||u.role==='admin')return res.status(404).json({error:'Application not found.'});await run('UPDATE users SET status=?,approved_at=CASE WHEN ?="approved" THEN CURRENT_TIMESTAMP ELSE approved_at END WHERE id=?',[status,status,u.id]);res.json({message:`Membership ${status}.`})});
app.post('/api/admin/announcements',admin,async(req,res)=>{const title=String(req.body.title||'').trim(),body=String(req.body.body||'').trim();if(!title||!body)return res.status(400).json({error:'Title and message are required.'});await run('INSERT INTO announcements(title,body,created_by) VALUES(?,?,?)',[title,body,req.session.user.id]);res.json({message:'Announcement published.'})});
app.get('/api/admin/members',admin,async(req,res)=>res.json(await all("SELECT id,full_name,father_name,branch,relationship,phone,email,status,created_at FROM users WHERE role!='admin' ORDER BY full_name")));
app.get('/health',(req,res)=>res.json({ok:true}));
init().then(()=>{const port=Number(process.env.PORT||3000);app.listen(port,'0.0.0.0',()=>console.log(`ONESHI FAMILY portal running on port ${port}`))}).catch(e=>{console.error('Startup failed',e);process.exit(1)});
