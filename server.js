// ============================================================
// drice-miter — Backend (Express + Turso + QR Payment + Slip Verify)
// ============================================================
import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import multer from 'multer';
import { createClient } from '@libsql/client';
import { fileURLToPath } from 'url';
import { Jimp } from 'jimp';
import jsQR from 'jsqr';
import Tesseract from 'tesseract.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Config ----------
const SESSION_HOURS = 24;
const PAYMENT_AMOUNT = Number(process.env.PAYMENT_AMOUNT || 500);
const PAYMENT_WINDOW_MIN = Number(process.env.PAYMENT_WINDOW_MIN || 15);
const PAYMENT_WINDOW_MS = PAYMENT_WINDOW_MIN * 60 * 1000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || '0647748563';
const EXPECTED_NAME = (process.env.RECEIVER_NAME || '').trim();
const EXPECTED_NAME_EN = (process.env.RECEIVER_NAME_EN || '').trim();
const EXPECTED_LAST4 = (process.env.RECEIVER_ACCOUNT_LAST4 || '').trim();

// ---------- ตรวจ env ----------
if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  console.error('❌ ต้องตั้งค่า TURSO_DATABASE_URL และ TURSO_AUTH_TOKEN');
  process.exit(1);
}

const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ---------- โฟลเดอร์ ----------
const PUBLIC_DIR = path.join(__dirname, 'public');
const SLIPS_DIR = path.join(PUBLIC_DIR, 'slips');
fs.mkdirSync(SLIPS_DIR, { recursive: true });

// ---------- Multer ----------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('รองรับเฉพาะไฟล์รูปภาพ'));
  },
});

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR, { dotfiles: 'deny', index: 'index.html' }));

// ============================================================
//  DB Init
// ============================================================
async function initDB() {
  await db.batch([
    `CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       username TEXT UNIQUE NOT NULL,
       password_hash TEXT NOT NULL,
       salt TEXT NOT NULL,
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       is_admin INTEGER NOT NULL DEFAULT 0,
       payment_status TEXT NOT NULL DEFAULT 'unpaid',
       payment_ref TEXT,
       payment_expires_at INTEGER,
       last_slip_url TEXT
     )`,
    `CREATE TABLE IF NOT EXISTS sessions (
       token TEXT PRIMARY KEY,
       user_id INTEGER NOT NULL,
       expires_at INTEGER NOT NULL
     )`,
    `CREATE TABLE IF NOT EXISTS payment_intents (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       ref TEXT UNIQUE NOT NULL,
       user_id INTEGER NOT NULL,
       username TEXT NOT NULL,
       amount INTEGER NOT NULL,
       status TEXT NOT NULL DEFAULT 'pending',
       created_at INTEGER NOT NULL,
       expires_at INTEGER NOT NULL,
       paid_at INTEGER,
       slip_qr_payload TEXT,
       slip_image_url TEXT,
       reject_reason TEXT
     )`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at)`,
    `CREATE INDEX IF NOT EXISTS idx_pay_ref       ON payment_intents(ref)`,
    `CREATE INDEX IF NOT EXISTS idx_pay_user      ON payment_intents(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_pay_qr        ON payment_intents(slip_qr_payload)`,
  ]);

  // migration เผื่อ DB เก่า
  const alters = [
    `ALTER TABLE users ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'unpaid'`,
    `ALTER TABLE users ADD COLUMN payment_ref TEXT`,
    `ALTER TABLE users ADD COLUMN payment_expires_at INTEGER`,
    `ALTER TABLE users ADD COLUMN last_slip_url TEXT`,
    `ALTER TABLE payment_intents ADD COLUMN detected_name TEXT`,
    `ALTER TABLE payment_intents ADD COLUMN detected_time TEXT`,
    `ALTER TABLE payment_intents ADD COLUMN ocr_text TEXT`,
    `ALTER TABLE payment_intents ADD COLUMN admin_note TEXT`,
  ];
  for (const sql of alters) {
    try { await db.execute(sql); } catch { /* column มีอยู่แล้ว */ }
  }

  // สร้างแอดมินเริ่มต้น
  const r = await db.execute({
    sql: 'SELECT id FROM users WHERE username=?',
    args: [ADMIN_USER],
  });
  if (r.rows.length === 0) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(ADMIN_PASS, salt, 64).toString('hex');
    const now = Date.now();
    const farFuture = now + 100 * 365 * 24 * 3600 * 1000;
    await db.execute({
      sql: `INSERT INTO users (username,password_hash,salt,created_at,expires_at,is_admin,payment_status)
            VALUES (?,?,?,?,?,1,'paid')`,
      args: [ADMIN_USER, hash, salt, now, farFuture],
    });
    console.log(`✅ สร้างแอดมินเริ่มต้น: ${ADMIN_USER}`);
  }

  await db.execute({ sql: 'DELETE FROM sessions WHERE expires_at < ?', args: [Date.now()] });
}

// ============================================================
//  Helpers
// ============================================================
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
const newToken = () => crypto.randomBytes(32).toString('hex');
const newRef = () =>
  'FD' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();

async function getUserFromReq(req) {
  const token = req.cookies?.session;
  if (!token) return null;
  const r = await db.execute({
    sql: `SELECT u.*, s.expires_at AS session_exp
          FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token = ? AND s.expires_at > ?`,
    args: [token, Date.now()],
  });
  return r.rows[0] || null;
}

function setSessionCookie(res, token, maxAgeMs) {
  res.cookie('session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: maxAgeMs,
  });
}

async function createOrGetPendingIntent(user) {
  const now = Date.now();

  // ✅ ล้าง pending เก่าที่หมดเวลาแล้ว
  await db.execute({
    sql: `UPDATE payment_intents SET status='expired'
          WHERE user_id=? AND status='pending' AND expires_at <= ?`,
    args: [user.id, now],
  });

  // หา pending ที่ยังไม่หมดอายุ
  const cur = await db.execute({
    sql: `SELECT * FROM payment_intents
          WHERE user_id=? AND status='pending' AND expires_at > ?
          ORDER BY id DESC LIMIT 1`,
    args: [user.id, now],
  });
  if (cur.rows.length > 0) return cur.rows[0];

  const ref = newRef();
  const payExp = now + PAYMENT_WINDOW_MS;
  await db.execute({
    sql: `INSERT INTO payment_intents (ref,user_id,username,amount,status,created_at,expires_at)
          VALUES (?,?,?,?,?,?,?)`,
    args: [ref, user.id, user.username, PAYMENT_AMOUNT, 'pending', now, payExp],
  });
  await db.execute({
    sql: `UPDATE users SET payment_ref=?, payment_expires_at=? WHERE id=?`,
    args: [ref, payExp, user.id],
  });
  const r = await db.execute({ sql: `SELECT * FROM payment_intents WHERE ref=?`, args: [ref] });
  return r.rows[0];
}

// ============================================================
//  AUTH
// ============================================================
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'กรอกข้อมูลไม่ครบ' });
  if (username.length < 3 || username.length > 32)
    return res.status(400).json({ error: 'ชื่อผู้ใช้ต้อง 3–32 ตัวอักษร' });
  if (!/^[A-Za-z0-9_\u0E00-\u0E7F]+$/.test(username))
    return res.status(400).json({ error: 'ชื่อผู้ใช้ใช้ได้เฉพาะตัวอักษร ตัวเลข _ และภาษาไทย' });
  if (password.length < 4) return res.status(400).json({ error: 'รหัสผ่านต้อง >= 4 ตัวอักษร' });

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPw(password, salt);
  const now = Date.now();
  const expires = 0;                    // ✅ ยังไม่จ่าย → ยังไม่มีเวลา

  try {
    const r = await db.execute({
      sql: `INSERT INTO users (username,password_hash,salt,created_at,expires_at,is_admin,payment_status)
            VALUES (?,?,?,?,?,0,'unpaid')`,
      args: [username, hash, salt, now, expires],
    });
    const userId = Number(r.lastInsertRowid);

    // ✅ session 24h ระหว่างรอจ่าย
    const token = newToken();
    await db.execute({
      sql: 'INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)',
      args: [token, userId, now + SESSION_HOURS * 3600 * 1000],
    });
    setSessionCookie(res, token, SESSION_HOURS * 3600 * 1000);

    // สร้าง payment intent ทันที
    const ref = newRef();
    const payExp = now + PAYMENT_WINDOW_MS;
    await db.execute({
      sql: `INSERT INTO payment_intents (ref,user_id,username,amount,status,created_at,expires_at)
            VALUES (?,?,?,?,?,?,?)`,
      args: [ref, userId, username, PAYMENT_AMOUNT, 'pending', now, payExp],
    });
    await db.execute({
      sql: `UPDATE users SET payment_ref=?, payment_expires_at=? WHERE id=?`,
      args: [ref, payExp, userId],
    });

    res.json({
      ok: true,
      username,
      expires_at: 0,
      is_admin: 0,
      need_payment: true,
      payment: { ref, amount: PAYMENT_AMOUNT, expires_at: payExp },
    });
  } catch (e) {
    if (String(e.message).includes('UNIQUE'))
      return res.status(400).json({ error: 'ชื่อผู้ใช้นี้ถูกใช้แล้ว' });
    console.error(e);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดภายใน' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'กรอกข้อมูลไม่ครบ' });

  const r = await db.execute({ sql: 'SELECT * FROM users WHERE username=?', args: [username] });
  if (r.rows.length === 0)
    return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  const u = r.rows[0];
  if (hashPw(password, u.salt) !== u.password_hash)
    return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

  const isUnpaid = !u.is_admin && u.payment_status !== 'paid';
const isExpired = !u.is_admin && u.payment_status === 'paid' && Date.now() > u.expires_at;
// ✅ ต้องจ่าย (ยังไม่จ่าย หรือ หมดอายุแล้ว)
const needNewPayment = isUnpaid || isExpired;

// ลบการ return 403 ออก — ให้ login ผ่าน แล้วเด้งไปหน้าจ่าย

  // ✅ ถ้าต้องจ่าย → ให้ session 24h ระหว่างดำเนินการ
const sessionExp = needNewPayment
  ? Date.now() + SESSION_HOURS * 3600 * 1000
  : u.expires_at;

  const token = newToken();
  await db.execute({
    sql: 'INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)',
    args: [token, u.id, sessionExp],
  });
  setSessionCookie(res, token, Math.max(60_000, sessionExp - Date.now()));

  let needPayment = false;
let payment = null;
if (needNewPayment) {
  const pi = await createOrGetPendingIntent(u);
  needPayment = true;
  payment = {
    ref: pi.ref,
    amount: pi.amount,
    expires_at: pi.expires_at,
    reason: isExpired ? 'expired' : 'unpaid',   // ✅ บอก frontend ว่ามาเพราะอะไร
  };
}

res.json({
  ok: true,
  username: u.username,
  expires_at: u.expires_at,
  is_admin: u.is_admin,
  need_payment: needPayment,
  payment,
});
});

app.post('/api/logout', async (req, res) => {
  const token = req.cookies?.session;
  if (token) await db.execute({ sql: 'DELETE FROM sessions WHERE token=?', args: [token] });
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/me', async (req, res) => {
  const u = await getUserFromReq(req);
  if (!u) return res.status(401).json({ error: 'ยังไม่ได้เข้าสู่ระบบ' });

  const isUnpaid = !u.is_admin && u.payment_status !== 'paid';
const isExpired = !u.is_admin && u.payment_status === 'paid' && Date.now() > u.expires_at;
const needNewPayment = isUnpaid || isExpired;

let needPayment = false;
let payment = null;
if (needNewPayment) {
  const pi = await createOrGetPendingIntent(u);
  needPayment = true;
  payment = {
    ref: pi.ref,
    amount: pi.amount,
    expires_at: pi.expires_at,
    reason: isExpired ? 'expired' : 'unpaid',
  };
}

res.json({
  username: u.username,
  expires_at: u.expires_at,
  is_admin: u.is_admin,
  created_at: u.created_at,
  need_payment: needPayment,
  payment,
});
  res.json({
    username: u.username,
    expires_at: u.expires_at,
    is_admin: u.is_admin,
    created_at: u.created_at,
    need_payment: needPayment,
    payment,
  });
});

// ============================================================
//  PAYMENT
// ============================================================
app.post('/api/payment/new', async (req, res) => {
  const u = await getUserFromReq(req);
  if (!u) return res.status(401).json({ error: 'ยังไม่ได้เข้าสู่ระบบ' });
  if (u.payment_status === 'paid') return res.json({ ok: true, already_paid: true });

  const now = Date.now();
  const ref = newRef();
  const payExp = now + PAYMENT_WINDOW_MS;

  await db.execute({
    sql: `INSERT INTO payment_intents (ref,user_id,username,amount,status,created_at,expires_at)
          VALUES (?,?,?,?,?,?,?)`,
    args: [ref, u.id, u.username, PAYMENT_AMOUNT, 'pending', now, payExp],
  });
  await db.execute({
    sql: `UPDATE users SET payment_ref=?, payment_expires_at=? WHERE id=?`,
    args: [ref, payExp, u.id],
  });

  res.json({ ok: true, ref, amount: PAYMENT_AMOUNT, expires_at: payExp });
});

app.get('/api/payment/status', async (req, res) => {
  const u = await getUserFromReq(req);
  if (!u) return res.status(401).json({ error: 'ยังไม่ได้เข้าสู่ระบบ' });

  if (u.payment_status === 'paid') return res.json({ ok: true, paid: true });

  const ref = req.query.ref;
  const r = await db.execute({
    sql: `SELECT * FROM payment_intents WHERE ref=? AND user_id=?`,
    args: [ref, u.id],
  });
  if (r.rows.length === 0) return res.json({ ok: true, paid: false });

  const pi = r.rows[0];
  res.json({
    ok: true,
    paid: pi.status === 'paid',
    status: pi.status,
    reject_reason: pi.reject_reason,
    expires_at: pi.expires_at,
  });
});

// ---- หลังตรวจสลิปผ่าน ให้ frontend refresh me ได้ทันที ----
app.get('/api/payment/paid', async (req, res) => {
  const u = await getUserFromReq(req);
  if (!u) return res.status(401).json({ error: 'ยังไม่ได้เข้าสู่ระบบ' });
  if (u.payment_status !== 'paid') return res.json({ ok: true, paid: false });
  if (Date.now() > u.expires_at)
    return res.status(403).json({ error: 'หมดอายุ' });

  res.json({
    ok: true,
    paid: true,
    username: u.username,
    expires_at: u.expires_at,
    is_admin: u.is_admin,
  });
});

app.post('/api/payment/upload-slip', upload.single('slip'), async (req, res) => {
  try {
    const u = await getUserFromReq(req);
    if (!u) return res.status(401).json({ error: 'ยังไม่ได้เข้าสู่ระบบ' });
    if (u.payment_status === 'paid') return res.json({ ok: true, paid: true });

    if (!req.file) return res.json({ ok: false, msg: 'กรุณาแนบรูปสลิป' });

    const { ref } = req.body || {};
    const pi = await db.execute({
      sql: `SELECT * FROM payment_intents WHERE ref=? AND user_id=?`,
      args: [ref, u.id],
    });
    if (pi.rows.length === 0) return res.json({ ok: false, msg: 'ไม่พบรายการชำระเงิน' });

    const intent = pi.rows[0];
    const now = Date.now();

    if (intent.status === 'paid') return res.json({ ok: true, paid: true, msg: 'ชำระแล้ว' });
    if (now > intent.expires_at)
      return res.json({
        ok: false,
        expired: true,
        msg: `❌ หมดเวลา ${PAYMENT_WINDOW_MIN} นาทีแล้ว กรุณากด "ขอเวลาใหม่"`,
      });

    // ==========================================
    //  LAYER 1: QR
    // ==========================================
    console.log('🔍 สแกน QR...');
    let qrPayload = null;
    try {
      const img = await Jimp.read(req.file.buffer);
      const qr = jsQR(
        new Uint8ClampedArray(img.bitmap.data),
        img.bitmap.width,
        img.bitmap.height
      );
      if (qr) qrPayload = qr.data;
    } catch (e) {
      console.error('QR decode error:', e.message);
    }
    if (!qrPayload) {
      return res.json({ ok: false, msg: '❌ ไม่พบ QR Code บนสลิป หรือรูปไม่ชัดเจน' });
    }
    console.log('📝 QR payload:', String(qrPayload).slice(0, 80), '...');

    // กันสลิปซ้ำ
    const used = await db.execute({
      sql: `SELECT id FROM payment_intents WHERE slip_qr_payload=? AND status='paid'`,
      args: [qrPayload],
    });
    if (used.rows.length > 0) {
      return res.json({ ok: false, msg: '❌ สลิปนี้ถูกใช้ยืนยันไปแล้ว' });
    }

    // ==========================================
    //  LAYER 2: OCR
    // ==========================================
    console.log('🔍 OCR กำลังอ่านข้อความ...');
    const { data: { text } } = await Tesseract.recognize(req.file.buffer, 'tha+eng');
    const clean = text.replace(/\s+/g, '');
    const cleanUpper = clean.toUpperCase();     // ✅ ย้ายขึ้นมาที่นี่

    // 1) ยอดเงิน
    const amtStr = String(PAYMENT_AMOUNT);
    if (!clean.includes(amtStr + '.00') && !clean.includes(amtStr)) {
      return res.json({ ok: false, msg: `❌ ไม่พบยอดเงิน ${PAYMENT_AMOUNT} บาทในสลิป` });
    }

    // 2) ชื่อผู้รับ — รองรับทั้งไทยและอังกฤษ
    const nameCandidates = [
      EXPECTED_NAME.replace(/\s+/g, ''),
      EXPECTED_NAME_EN.replace(/\s+/g, '').toUpperCase(),
    ].filter(Boolean);

    if (nameCandidates.length > 0) {
      const matched = nameCandidates.find(n => {
        if (/^[A-Z0-9]+$/.test(n)) return cleanUpper.includes(n);
        return clean.includes(n);
      });

      if (!matched) {
        return res.json({
          ok: false,
          msg: `❌ ชื่อผู้รับไม่ตรงกับร้าน (ต้องมี "${EXPECTED_NAME}" หรือ "${EXPECTED_NAME_EN}")`,
        });
      }
      console.log('✅ ชื่อผู้รับตรง:', matched);
    }

    // 3) เลข 4 ตัวท้าย
    if (EXPECTED_LAST4 && !clean.includes(EXPECTED_LAST4))
      return res.json({ ok: false, msg: '❌ เลขบัญชี 4 ตัวท้ายไม่ตรง' });

    // 4) เวลา
    const tm = clean.match(/(\d{2}):(\d{2})/);
    if (tm) {
      const hh = +tm[1], mm = +tm[2];
      const bkk = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' }));
      let diff = (bkk.getHours() * 60 + bkk.getMinutes()) - (hh * 60 + mm);
      if (diff < -1000) diff += 1440;
      if (diff > PAYMENT_WINDOW_MIN)
        return res.json({ ok: false, msg: `❌ สลิปเก่าเกิน ${PAYMENT_WINDOW_MIN} นาที` });
      if (diff < -5) return res.json({ ok: false, msg: '❌ เวลาในสลิปผิดปกติ' });
    }

    // ==========================================
    //  ผ่าน — บันทึก + อนุมัติ + เริ่มนับ 24h
    // ==========================================
    const ext = path.extname(req.file.originalname) || '.jpg';
    const fname = `slip_${u.username}_${now}${ext}`;
    const fpath = path.join(SLIPS_DIR, fname);
    fs.writeFileSync(fpath, req.file.buffer);
    const slipUrl = `/slips/${fname}`;

    // ดึงข้อมูลที่ตรวจเจอ
    const detectedTime = (tm ? `${tm[1]}:${tm[2]}` : null);
    const detectedName =
      (EXPECTED_NAME && clean.includes(EXPECTED_NAME.replace(/\s+/g, '')) ? EXPECTED_NAME : null) ||
      (EXPECTED_NAME_EN && cleanUpper.includes(EXPECTED_NAME_EN.replace(/\s+/g, '').toUpperCase()) ? EXPECTED_NAME_EN : null);

    await db.execute({
      sql: `UPDATE payment_intents
            SET status='paid', paid_at=?, slip_qr_payload=?, slip_image_url=?,
                detected_name=?, detected_time=?, ocr_text=?
            WHERE id=?`,
      args: [now, qrPayload, slipUrl, detectedName, detectedTime, clean.slice(0, 2000), intent.id],
    });

    // ✅ ต่อเวลาจากเดิม (ถ้ายังไม่หมด) หรือเริ่มใหม่จาก now (ถ้าหมดแล้ว)
const base = Math.max(now, u.expires_at || 0);
const userExpiry = base + SESSION_HOURS * 3600 * 1000;

await db.execute({
  sql: `UPDATE users SET payment_status='paid', last_slip_url=?, expires_at=? WHERE id=?`,
  args: [slipUrl, userExpiry, u.id],
});
    await db.execute({
      sql: 'UPDATE sessions SET expires_at=? WHERE user_id=?',
      args: [userExpiry, u.id],
    });

    console.log(`✅ อนุมัติสลิป: ${u.username} (ref=${ref}) — หมดอายุ ${new Date(userExpiry).toLocaleString('th-TH')}`);
    res.json({ ok: true, paid: true, msg: '✅ ตรวจสอบสลิปสำเร็จ!' });
  } catch (e) {
    console.error('verify-slip error:', e);
    res.status(500).json({ ok: false, msg: 'อ่านภาพไม่สำเร็จ: ' + e.message });
  }
});

// ============================================================
//  Admin
// ============================================================
async function requireAdmin(req, res, next) {
  const u = await getUserFromReq(req);
  if (!u || !u.is_admin) return res.status(403).json({ error: 'ต้องเป็นแอดมิน' });
  req.admin = u;
  next();
}

app.get('/api/admin/users', requireAdmin, async (_req, res) => {
  const r = await db.execute(
    `SELECT id, username, created_at, expires_at, is_admin, payment_status, last_slip_url
     FROM users ORDER BY id ASC`
  );
  res.json(r.rows);
});

app.get('/api/admin/payments', requireAdmin, async (_req, res) => {
  const r = await db.execute(
    `SELECT * FROM payment_intents ORDER BY created_at DESC LIMIT 200`
  );
  res.json(r.rows);
});

app.get('/api/admin/users/:id/slips', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const r = await db.execute({
    sql: `SELECT id, ref, amount, status, created_at, expires_at, paid_at,
                 slip_image_url, slip_qr_payload, detected_name, detected_time,
                 ocr_text, admin_note, reject_reason
          FROM payment_intents
          WHERE user_id=?
          ORDER BY id DESC`,
    args: [id],
  });
  res.json(r.rows);
});

app.post('/api/admin/payments/:id/note', requireAdmin, async (req, res) => {
  const { note } = req.body || {};
  const id = Number(req.params.id);
  if (typeof note !== 'string' || note.length > 500)
    return res.status(400).json({ error: 'หมายเหตุไม่ถูกต้อง' });

  await db.execute({
    sql: 'UPDATE payment_intents SET admin_note=? WHERE id=?',
    args: [note, id],
  });
  res.json({ ok: true });
});

app.delete('/api/admin/payments/:id/slip', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const r = await db.execute({
    sql: 'SELECT user_id, slip_image_url FROM payment_intents WHERE id=?',
    args: [id],
  });
  if (r.rows.length === 0) return res.status(404).json({ error: 'ไม่พบสลิป' });

  const { user_id, slip_image_url } = r.rows[0];

  if (slip_image_url) {
    const fname = path.basename(slip_image_url);
    const fpath = path.join(SLIPS_DIR, fname);
    try { fs.unlinkSync(fpath); } catch { /* ไฟล์ถูกลบไปแล้ว */ }
  }

  await db.execute({
    sql: `UPDATE payment_intents
          SET status='rejected', slip_image_url=NULL, slip_qr_payload=NULL,
              reject_reason='admin rejected', detected_name=NULL, detected_time=NULL
          WHERE id=?`,
    args: [id],
  });
  // ✅ reset กลับเป็น unpaid + ล้างเวลา
  await db.execute({
    sql: `UPDATE users SET payment_status='unpaid', last_slip_url=NULL, expires_at=0 WHERE id=?`,
    args: [user_id],
  });
  // ลบ session ทั้งหมดของ user นี้ → บังคับ login ใหม่
  await db.execute({
    sql: 'DELETE FROM sessions WHERE user_id=?',
    args: [user_id],
  });

  res.json({ ok: true });
});

app.post('/api/admin/users/:id/approve-payment', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const now = Date.now();

  const cur = await db.execute({
    sql: 'SELECT expires_at FROM users WHERE id=?',
    args: [id],
  });
  if (cur.rows.length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });

  // ✅ ถ้ายังไม่มีเวลา (0) → ให้ 24h / มีอยู่แล้ว → ต่อจากเดิม
  const base = Math.max(now, cur.rows[0].expires_at || 0);
  const newExp = base + SESSION_HOURS * 3600 * 1000;

  await db.execute({
    sql: `UPDATE users SET payment_status='paid', expires_at=? WHERE id=? AND is_admin=0`,
    args: [newExp, id],
  });
  await db.execute({
    sql: `UPDATE payment_intents SET status='paid', paid_at=?
          WHERE user_id=? AND status='pending'`,
    args: [now, id],
  });
  await db.execute({
    sql: 'UPDATE sessions SET expires_at=? WHERE user_id=?',
    args: [newExp, id],
  });

  res.json({ ok: true, expires_at: newExp });
});

app.post('/api/admin/users/:id/extend', requireAdmin, async (req, res) => {
  const { hours } = req.body || {};
  const id = Number(req.params.id);
  if (!Number.isFinite(hours) || hours === 0 || Math.abs(hours) > 100000)
    return res.status(400).json({ error: 'hours ไม่ถูกต้อง' });

  const r = await db.execute({
    sql: 'SELECT expires_at, is_admin FROM users WHERE id=?',
    args: [id],
  });
  if (r.rows.length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  if (r.rows[0].is_admin) return res.status(400).json({ error: 'แก้เวลาแอดมินไม่ได้' });

  const base = Math.max(Date.now(), r.rows[0].expires_at);
  const newExp = Math.max(Date.now(), base + hours * 3600 * 1000);

  await db.execute({ sql: 'UPDATE users SET expires_at=? WHERE id=?', args: [newExp, id] });
  await db.execute({
    sql: 'UPDATE sessions SET expires_at=? WHERE user_id=?',
    args: [newExp, id],
  });
  res.json({ ok: true, expires_at: newExp });
});

app.post('/api/admin/users/:id/set-time', requireAdmin, async (req, res) => {
  const { expires_at } = req.body || {};
  const id = Number(req.params.id);
  if (!Number.isFinite(expires_at) || expires_at < 0)
    return res.status(400).json({ error: 'expires_at ไม่ถูกต้อง' });

  const r = await db.execute({
    sql: 'SELECT is_admin, expires_at FROM users WHERE id=?',
    args: [id],
  });
  if (r.rows.length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  if (r.rows[0].is_admin) return res.status(400).json({ error: 'แก้เวลาแอดมินไม่ได้' });

  // ✅ ถ้าตั้งเวลาในอนาคต → ถือว่าจ่ายแล้ว + ตั้งเวลา
  const isFuture = expires_at > Date.now();

  if (isFuture) {
    await db.execute({
      sql: `UPDATE users SET expires_at=?, payment_status='paid' WHERE id=?`,
      args: [expires_at, id],
    });
    // อัปเดต payment_intent ล่าสุดให้เป็น paid ถ้ามี pending
    await db.execute({
      sql: `UPDATE payment_intents
            SET status='paid', paid_at=?
            WHERE user_id=? AND status IN ('pending','expired')`,
      args: [Date.now(), id],
    });
  } else {
    // ตั้งในอดีต → หมดอายุทันที
    await db.execute({
      sql: `UPDATE users SET expires_at=? WHERE id=?`,
      args: [expires_at, id],
    });
  }

  await db.execute({
    sql: 'UPDATE sessions SET expires_at=? WHERE user_id=?',
    args: [expires_at, id],
  });

  res.json({ ok: true, expires_at });
});

app.post('/api/admin/users/:id/password', requireAdmin, async (req, res) => {
  const { password } = req.body || {};
  const id = Number(req.params.id);
  if (!password || password.length < 4)
    return res.status(400).json({ error: 'รหัสผ่านต้อง >= 4 ตัวอักษร' });

  const salt = crypto.randomBytes(16).toString('hex');
  const hash = hashPw(password, salt);
  await db.execute({
    sql: 'UPDATE users SET password_hash=?, salt=? WHERE id=? AND is_admin=0',
    args: [hash, salt, id],
  });
  await db.execute({ sql: 'DELETE FROM sessions WHERE user_id=?', args: [id] });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const r = await db.execute({ sql: 'SELECT is_admin FROM users WHERE id=?', args: [id] });
  if (r.rows.length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
  if (r.rows[0].is_admin) return res.status(400).json({ error: 'ลบแอดมินไม่ได้' });

  await db.batch([
    { sql: 'DELETE FROM sessions WHERE user_id=?', args: [id] },
    { sql: 'DELETE FROM payment_intents WHERE user_id=?', args: [id] },
    { sql: 'DELETE FROM users WHERE id=?', args: [id] },
  ]);
  res.json({ ok: true });
});

// ============================================================
//  Auto-expire pending payments
// ============================================================
setInterval(async () => {
  try {
    await db.execute({
      sql: `UPDATE payment_intents SET status='expired'
            WHERE status='pending' AND expires_at < ?`,
      args: [Date.now()],
    });
  } catch (e) {
    console.error('auto-expire error:', e);
  }
}, 60 * 1000);

// ============================================================
//  Fallback + Error
// ============================================================
app.get('*', (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'server error' });
});

// ============================================================
//  Start
// ============================================================
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 drice-miter → http://localhost:${PORT}`);
    });
  })
  .catch((e) => {
    console.error('❌ initDB ล้มเหลว:', e);
    process.exit(1);
  });
