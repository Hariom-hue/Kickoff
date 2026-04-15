require("dotenv").config();

const express    = require("express");
const cors       = require("cors");
const mongoose   = require("mongoose");
const multer     = require("multer");
const cloudinary = require("cloudinary").v2;
const bcrypt     = require("bcrypt");
const jwt        = require("jsonwebtoken");
const crypto     = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME?.trim(),
  api_key:    process.env.API_KEY?.trim(),
  api_secret: process.env.API_SECRET?.trim()
});

const storage = multer.memoryStorage();
const upload  = multer({ storage });

/* ════════════════════════════════════════════════
   📧  NODEMAILER — single transporter, two helpers
   ════════════════════════════════════════════════ */
  const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false
  }
});            
transporter.verify((error, success) => {
  if (error) {
    console.error("❌ EMAIL CONFIG ERROR:", error.message);
  } else {
    console.log("✅ Email transporter ready");
  }
});

// User OTP email (signup / login)
async function sendOTPEmail(to, code, purpose = "login") {
  const isSignup = purpose === "signup";
  await transporter.sendMail({
    from:    `"KICKOFF Store" <${process.env.MAIL_USER}>`,
    to,
    subject: `KICKOFF — Your ${isSignup ? "Signup" : "Login"} Code`,
    html: `
      <div style="background:#0a0a0a;padding:40px;font-family:sans-serif;max-width:480px;margin:0 auto;border-radius:16px;">
        <h1 style="font-size:2rem;letter-spacing:0.1em;margin:0 0 6px;">
          <span style="color:#fff;">KICK</span><span style="color:#c8ff00;">OFF</span>
        </h1>
        <p style="color:#555;font-size:11px;letter-spacing:0.15em;text-transform:uppercase;margin:0 0 32px;">
          ${isSignup ? "Account Verification" : "Secure Login"}
        </p>
        <p style="color:#888;font-size:14px;margin-bottom:20px;">Your one-time verification code:</p>
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:28px;text-align:center;margin-bottom:24px;">
          <span style="font-size:2.8rem;font-weight:900;letter-spacing:0.3em;color:#c8ff00;">${code}</span>
        </div>
        <p style="color:#555;font-size:12px;line-height:1.6;">
          This code expires in <strong style="color:#888;">10 minutes</strong>.<br/>
          If you didn't request this, please ignore this email.
        </p>
        <div style="margin-top:28px;padding-top:20px;border-top:1px solid #1a1a1a;">
          <p style="color:#2a2a2a;font-size:11px;">© 2025 KICKOFF Store</p>
        </div>
      </div>
    `,
  });
}

// Admin OTP email
async function sendAdminOTPEmail(to, code) {
  await transporter.sendMail({
    from:    `"KICKOFF Admin" <${process.env.MAIL_USER}>`,
    to,
    subject: "KICKOFF Admin — Your Login Code",
    html: `
      <div style="background:#0a0a0a;padding:40px;font-family:sans-serif;max-width:480px;margin:0 auto;border-radius:16px;">
        <h1 style="font-size:2rem;letter-spacing:0.1em;margin:0 0 6px;">
          <span style="color:#fff;">KICK</span><span style="color:#c8ff00;">OFF</span>
        </h1>
        <p style="color:#555;font-size:11px;letter-spacing:0.15em;text-transform:uppercase;margin:0 0 32px;">Admin Portal</p>
        <p style="color:#888;font-size:14px;margin-bottom:20px;">Your admin login code:</p>
        <div style="background:#111;border:1px solid #1e1e1e;border-radius:12px;padding:28px;text-align:center;margin-bottom:24px;">
          <span style="font-size:2.8rem;font-weight:900;letter-spacing:0.3em;color:#c8ff00;">${code}</span>
        </div>
        <p style="color:#555;font-size:12px;line-height:1.6;">
          Expires in <strong style="color:#888;">5 minutes</strong>.<br/>
          If you didn't request this, your admin panel may be under attack.
        </p>
        <div style="margin-top:28px;padding-top:20px;border-top:1px solid #1a1a1a;">
          <p style="color:#2a2a2a;font-size:11px;">© 2025 KICKOFF Store — All attempts are logged.</p>
        </div>
      </div>
    `,
  });
}

/* ═══════════════════════════════════
   🔒 RATE LIMITER
   ═══════════════════════════════════ */
const rateLimits = new Map();
function isRateLimited(key, max = 5, windowMs = 60_000) {
  const now  = Date.now();
  const data = rateLimits.get(key) || { count: 0, reset: now + windowMs };
  if (now > data.reset) { data.count = 0; data.reset = now + windowMs; }
  data.count++;
  rateLimits.set(key, data);
  return data.count > max;
}

/* ═══════════════════════════════════
   🔐 ADMIN MODEL
   ═══════════════════════════════════ */
const adminSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true },
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ["superadmin","admin","editor"], default: "admin" },
  active:    { type: Boolean, default: true },
  lastLogin: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
});
const Admin = mongoose.model("Admin", adminSchema);

async function seedAdmin() {
  const count = await Admin.countDocuments();
  if (count === 0) {
    const username = process.env.ADMIN_USERNAME || "kickoff";
    const password = process.env.ADMIN_PASSWORD || "kickoff.com1212";
    const email    = process.env.ADMIN_EMAIL    || "ombggaikwad@gmail.com";
    const hashed   = await bcrypt.hash(password, 12);
    await new Admin({ username, email, password: hashed, role: "superadmin" }).save();
    console.log(`✅ Admin seeded  user:${username}  email:${email}`);
  }
}
mongoose.connection.once("open", seedAdmin);

/* ═══════════════════════════════════
   🛡️  JWT MIDDLEWARE
   ═══════════════════════════════════ */
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "kickoff_admin_jwt_CHANGE_ME";

function requireAdmin(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const payload = jwt.verify(token, ADMIN_JWT_SECRET);
    if (payload.role !== "admin") return res.status(403).json({ error: "Forbidden" });
    req.admin = payload;
    next();
  } catch { return res.status(401).json({ error: "Invalid or expired token" }); }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.admin?.dbRole)) return res.status(403).json({ error: "Insufficient permissions" });
    next();
  };
}

/* ═══════════════════════════════════
   🔐 ADMIN AUTH
   ═══════════════════════════════════ */
const pendingSessions = new Map();

app.post("/admin-login", async (req, res) => {
  const ip = req.ip || "unknown";
  if (isRateLimited(`adminlogin:${ip}`, 5, 60_000))
    return res.status(429).json({ success: false, error: "Too many attempts. Wait 60s." });

  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, error: "Username and password required" });

  try {
    const admin = await Admin.findOne({ username: username.trim().toLowerCase() });
    if (!admin || !admin.active) {
      console.warn(`⚠️  Failed admin login — unknown user "${username}"`);
      return res.status(401).json({ success: false });
    }
    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      console.warn(`⚠️  Failed admin login — wrong password for "${username}"`);
      return res.status(401).json({ success: false });
    }

    const otp          = Math.floor(100000 + Math.random() * 900000).toString();
    const sessionToken = crypto.randomBytes(32).toString("hex");
    pendingSessions.set(sessionToken, { adminId: admin._id.toString(), otp, ip, at: Date.now() });
    for (const [k, v] of pendingSessions) if (Date.now() - v.at > 300_000) pendingSessions.delete(k);

    try {
      await sendAdminOTPEmail(admin.email, otp);
      console.log(`📧 Admin OTP sent to ${admin.email}`);
    } catch (mailErr) {
      console.log(`\n🔐 [EMAIL FAILED — DEV FALLBACK]`);
      console.log(`   Admin OTP  : ${otp}`);
      console.log(`   For user   : ${username}  (${admin.email})`);
      console.log(`   Error      : ${mailErr.message}\n`);
    }
    res.json({ success: true, token: sessionToken });
  } catch (err) {
    console.error("admin-login error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/admin-verify", async (req, res) => {
  const ip = req.ip || "unknown";
  if (isRateLimited(`adminverify:${ip}`, 5, 60_000))
    return res.status(429).json({ success: false, error: "Too many attempts." });

  const { token, code } = req.body;
  if (!token || !pendingSessions.has(token))
    return res.status(401).json({ success: false, error: "Invalid or expired session. Login again." });

  const session = pendingSessions.get(token);
  if (Date.now() - session.at > 300_000) {
    pendingSessions.delete(token);
    return res.status(401).json({ success: false, error: "Code expired. Login again." });
  }
  if (code !== session.otp) return res.status(401).json({ success: false, error: "Invalid code" });
  pendingSessions.delete(token);

  try {
    const admin = await Admin.findById(session.adminId);
    if (!admin || !admin.active) return res.status(401).json({ success: false, error: "Account deactivated" });
    await Admin.findByIdAndUpdate(admin._id, { lastLogin: new Date() });
    const adminToken = jwt.sign(
      { role: "admin", dbRole: admin.role, adminId: admin._id.toString(), username: admin.username, ip },
      ADMIN_JWT_SECRET, { expiresIn: "4h" }
    );
    console.log(`✅ Admin login — "${admin.username}" (${admin.role})`);
    res.json({ success: true, adminToken });
  } catch (err) {
    console.error("admin-verify error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post("/admin-change-password", requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 8)
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  try {
    const admin = await Admin.findById(req.admin.adminId);
    const match = await bcrypt.compare(currentPassword, admin.password);
    if (!match) return res.status(401).json({ error: "Current password incorrect" });
    admin.password = await bcrypt.hash(newPassword, 12);
    await admin.save();
    res.json({ message: "Password updated ✅" });
  } catch { res.status(500).json({ error: "Failed to update password" }); }
});

/* ═══════════════════════════════════
   👤 USER MODEL + PROFILE
   ═══════════════════════════════════ */
const userSchema = new mongoose.Schema({ email: String, password: String });
const User = mongoose.model("User", userSchema);

const userProfileSchema = new mongoose.Schema({
  email:          { type: String, required: true, unique: true },
  name:           { type: String, default: "" },
  phone:          { type: String, default: "" },
  notifications:  { type: Boolean, default: true },
  savedAddresses: { type: Array, default: [] },
  createdAt:      { type: Date, default: Date.now },
});
const UserProfile = mongoose.model("UserProfile", userProfileSchema);

/* ═══════════════════════════════════
   🔑 USER OTP AUTH
   ═══════════════════════════════════ */
const userOTPStore = new Map();

app.post("/auth/send-otp", async (req, res) => {
  const { email, password, purpose } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  if (isRateLimited(`userotp:${email}`, 5, 60_000))
    return res.status(429).json({ error: "Too many attempts. Wait 60s." });

  if (purpose === "signup") {
    if (!password || password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: "Account already exists. Please sign in." });
  }

  if (purpose === "login") {
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (!existing) return res.status(404).json({ error: "No account found. Please create one." });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  userOTPStore.set(email.toLowerCase(), {
    otp, purpose,
    password: password || null,
    expiresAt: Date.now() + 10 * 60 * 1000,
  });
  for (const [k, v] of userOTPStore) if (Date.now() > v.expiresAt) userOTPStore.delete(k);

  try {
    await sendOTPEmail(email, otp, purpose);
    console.log(`📧 User OTP (${purpose}) sent to ${email}`);
    res.json({ success: true, message: "OTP sent to your email" });
  } catch (mailErr) {
    console.log(`\n📧 [EMAIL FAILED — DEV FALLBACK]`);
    console.log(`   User OTP   : ${otp}`);
    console.log(`   For email  : ${email} (${purpose})`);
    console.log(`   Error      : ${mailErr.message}\n`);
    res.json({ success: true, message: "OTP sent (check Railway logs — email failed)" });
  }
});

app.post("/auth/verify-signup", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

  const entry = userOTPStore.get(email.toLowerCase());
  if (!entry) return res.status(400).json({ error: "OTP expired or not requested. Send again." });
  if (Date.now() > entry.expiresAt) {
    userOTPStore.delete(email.toLowerCase());
    return res.status(400).json({ error: "OTP expired. Please request a new one." });
  }
  if (entry.otp !== otp.trim()) return res.status(400).json({ error: "Invalid OTP. Try again." });
  if (entry.purpose !== "signup") return res.status(400).json({ error: "Wrong OTP type" });

  userOTPStore.delete(email.toLowerCase());

  try {
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: "Account already exists. Please sign in." });

    const hashed = await bcrypt.hash(entry.password, 10);
    await new User({ email: email.toLowerCase(), password: hashed }).save();

    await UserProfile.findOneAndUpdate(
      { email: email.toLowerCase() },
      { email: email.toLowerCase() },
      { upsert: true, new: true }
    );

    const token = jwt.sign({ email: email.toLowerCase() }, process.env.JWT_SECRET || "secret123", { expiresIn: "7d" });
    console.log(`✅ New user signed up: ${email}`);
    res.json({ success: true, token, message: "Account created ✅" });
  } catch (err) {
    console.error("verify-signup error:", err);
    res.status(500).json({ error: "Failed to create account" });
  }
});

app.post("/auth/verify-login", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

  const entry = userOTPStore.get(email.toLowerCase());
  if (!entry) return res.status(400).json({ error: "OTP expired or not requested. Send again." });
  if (Date.now() > entry.expiresAt) {
    userOTPStore.delete(email.toLowerCase());
    return res.status(400).json({ error: "OTP expired. Please request a new one." });
  }
  if (entry.otp !== otp.trim()) return res.status(400).json({ error: "Invalid OTP. Try again." });
  if (entry.purpose !== "login") return res.status(400).json({ error: "Wrong OTP type" });

  userOTPStore.delete(email.toLowerCase());

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: "Account not found" });

    await UserProfile.findOneAndUpdate(
      { email: email.toLowerCase() },
      { email: email.toLowerCase() },
      { upsert: true, new: true }
    );

    const token = jwt.sign({ email: email.toLowerCase() }, process.env.JWT_SECRET || "secret123", { expiresIn: "7d" });
    console.log(`✅ User logged in: ${email}`);
    res.json({ success: true, token, message: "Login successful ✅" });
  } catch (err) {
    console.error("verify-login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

/* ═══════════════════════════════════
   👤 USER PROFILE ROUTES
   ═══════════════════════════════════ */
app.get("/user/profile", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email required" });
  try {
    const profile = await UserProfile.findOne({ email: email.toLowerCase() });
    if (!profile) {
      const newProfile = await UserProfile.create({ email: email.toLowerCase() });
      return res.json(newProfile);
    }
    res.json(profile);
  } catch { res.status(500).json({ error: "Failed to fetch profile" }); }
});

app.patch("/user/profile", async (req, res) => {
  const { email, ...updates } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });
  try {
    const profile = await UserProfile.findOneAndUpdate(
      { email: email.toLowerCase() },
      { $set: updates },
      { new: true, upsert: true }
    );
    res.json(profile);
  } catch { res.status(500).json({ error: "Failed to update profile" }); }
});

/* Legacy auth (backward compat) */
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "User already exists" });
    const hashed = await bcrypt.hash(password, 10);
    await new User({ email, password: hashed }).save();
    res.json({ message: "User created ✅" });
  } catch { res.status(500).json({ error: "Signup failed" }); }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ email }, process.env.JWT_SECRET || "secret123", { expiresIn: "7d" });
    res.json({ message: "Login successful ✅", token });
  } catch { res.status(500).json({ error: "Login failed" }); }
});

/* ═══════════════════════════════════
   🏆 LEAGUES
   ═══════════════════════════════════ */
const leagueSchema = new mongoose.Schema({
  name: { type: String, required: true }, sport: { type: String, default: "Football" },
  logo: { type: String, default: "" }, country: { type: String, default: "" },
  active: { type: Boolean, default: true }, order: { type: Number, default: 0 },
});
const League = mongoose.model("League", leagueSchema);

async function seedLeagues() {
  const count = await League.countDocuments();
  if (count === 0) {
    await League.insertMany([
      { name: "IPL", sport: "Cricket", country: "India", order: 1 },
      { name: "FIFA World Cup", sport: "Football", country: "Global", order: 2 },
      { name: "La Liga", sport: "Football", country: "Spain", order: 3 },
      { name: "Premier League", sport: "Football", country: "England", order: 4 },
      { name: "NBA", sport: "Basketball", country: "USA", order: 5 },
      { name: "Pro Kabaddi", sport: "Kabaddi", country: "India", order: 6 },
    ]);
    console.log("✅ Default leagues seeded");
  }
}
mongoose.connection.once("open", seedLeagues);

app.get("/leagues", async (req, res) => {
  try { res.json(await League.find({ active: true }).sort({ order: 1 })); }
  catch { res.status(500).json({ error: "Failed to fetch leagues" }); }
});
app.post("/leagues", requireAdmin, async (req, res) => {
  try { res.status(201).json(await new League(req.body).save()); }
  catch { res.status(500).json({ error: "Failed to create league" }); }
});
app.put("/leagues/:id", requireAdmin, async (req, res) => {
  try { res.json(await League.findByIdAndUpdate(req.params.id, req.body, { new: true })); }
  catch { res.status(500).json({ error: "Failed to update league" }); }
});
app.delete("/leagues/:id", requireAdmin, async (req, res) => {
  try { await League.findByIdAndDelete(req.params.id); res.json({ message: "Deleted ✅" }); }
  catch { res.status(500).json({ error: "Failed to delete league" }); }
});

/* ═══════════════════════════════════
   🔥 PRODUCTS
   ═══════════════════════════════════ */
const productSchema = new mongoose.Schema({
  name: String, category: String, league: { type: String, default: "" },
  price: Number, image: String, backImage: { type: String, default: "" },
  highlights: {
    color: { type: String, default: "" }, pattern: { type: String, default: "" },
    fabric: { type: String, default: "" }, fit: { type: String, default: "" },
    occasion: { type: String, default: "" }, material: { type: String, default: "" },
  }
});
const Product = mongoose.model("Product", productSchema);

app.get("/products", async (req, res) => {
  try {
    const filter = {};
    if (req.query.league)   filter.league   = req.query.league;
    if (req.query.category) filter.category = req.query.category;
    res.json(await Product.find(filter));
  } catch { res.status(500).json({ error: "Failed to fetch products" }); }
});
app.post("/add-product", requireAdmin, async (req, res) => {
  try { const p = new Product(req.body); await p.save(); res.json({ message: "Product added ✅", product: p }); }
  catch { res.status(500).json({ error: "Failed to add product" }); }
});
app.put("/update-product/:id", requireAdmin, async (req, res) => {
  try { res.json({ message: "Updated ✅", product: await Product.findByIdAndUpdate(req.params.id, req.body, { new: true }) }); }
  catch { res.status(500).json({ error: "Failed to update product" }); }
});
app.delete("/delete-product/:id", requireAdmin, async (req, res) => {
  try { await Product.findByIdAndDelete(req.params.id); res.json({ message: "Deleted ✅" }); }
  catch { res.status(500).json({ error: "Failed to delete" }); }
});

app.post("/upload", requireAdmin, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const b64    = Buffer.from(req.file.buffer).toString("base64");
    const result = await cloudinary.uploader.upload("data:" + req.file.mimetype + ";base64," + b64, { folder: "kickoff-store" });
    res.json({ url: result.secure_url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

/* ═══════════════════════════════════
   📦 ORDERS
   ═══════════════════════════════════ */
const orderSchema = new mongoose.Schema({
  items: Array, total: Number, user: String,
  address: String, paymentId: String, paymentMethod: String,
  appliedOffer: String, date: { type: Date, default: Date.now }
});
const Order = mongoose.model("Order", orderSchema);

app.post("/order", async (req, res) => {
  try { const o = new Order(req.body); await o.save(); res.json({ message: "Order placed ✅", orderId: o._id }); }
  catch { res.status(500).json({ error: "Failed to place order" }); }
});
app.get("/orders", requireAdmin, async (req, res) => {
  try { res.json(await Order.find().sort({ date: -1 })); }
  catch { res.status(500).json({ error: "Failed to fetch orders" }); }
});
app.get("/orders/user/:email", async (req, res) => {
  try { res.json(await Order.find({ user: decodeURIComponent(req.params.email) }).sort({ date: -1 })); }
  catch { res.status(500).json({ error: "Failed to fetch user orders" }); }
});

/* ═══════════════════════════════════
   ⭐ REVIEWS
   ═══════════════════════════════════ */
const reviewSchema = new mongoose.Schema({
  productId: { type: String, required: true }, user: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 }, title: { type: String, default: "" },
  comment: { type: String, required: true }, helpful: { type: Number, default: 0 },
  notHelpful: { type: Number, default: 0 }, date: { type: Date, default: Date.now }
});
const Review = mongoose.model("Review", reviewSchema);

app.get("/reviews/:productId", async (req, res) => {
  try {
    const reviews = await Review.find({ productId: req.params.productId }).sort({ date: -1 });
    const total   = reviews.length;
    const avg     = total ? parseFloat((reviews.reduce((s, r) => s + r.rating, 0) / total).toFixed(1)) : 0;
    const starCounts = [5,4,3,2,1].map(star => {
      const count = reviews.filter(r => r.rating === star).length;
      return { star, count, pct: total ? Math.round((count / total) * 100) : 0 };
    });
    res.json({ reviews, avg, total, starCounts });
  } catch { res.status(500).json({ error: "Failed to fetch reviews" }); }
});
app.post("/reviews/:productId", async (req, res) => {
  const { user, rating, title, comment } = req.body;
  if (!user || !rating || !comment) return res.status(400).json({ error: "user, rating and comment required" });
  try {
    const existing = await Review.findOne({ productId: req.params.productId, user });
    if (existing) return res.status(400).json({ error: "You have already reviewed this product" });
    const review = new Review({ productId: req.params.productId, user, rating: parseInt(rating), title, comment });
    await review.save();
    res.status(201).json(review);
  } catch { res.status(500).json({ error: "Failed to save review" }); }
});
app.post("/reviews/:productId/:reviewId/vote", async (req, res) => {
  const { type } = req.body;
  try {
    const update = type === "helpful" ? { $inc: { helpful: 1 } } : { $inc: { notHelpful: 1 } };
    const review = await Review.findByIdAndUpdate(req.params.reviewId, update, { new: true });
    if (!review) return res.status(404).json({ error: "Review not found" });
    res.json(review);
  } catch { res.status(500).json({ error: "Vote failed" }); }
});

/* ═══════════════════════════════════
   🏦 OFFERS
   ═══════════════════════════════════ */
const offerSchema = new mongoose.Schema({
  tag: { type: String, default: null }, icon: { type: String, default: "🏦" },
  label: { type: String, required: true }, sub: { type: String, required: true },
  type: { type: String, required: true }, discount: { type: Number, required: true },
  active: { type: Boolean, default: true }
});
const Offer = mongoose.model("Offer", offerSchema);

async function seedOffers() {
  const count = await Offer.countDocuments();
  if (count === 0) {
    await Offer.insertMany([
      { tag: "Best value for you", icon: "🏦", label: "₹50 off", sub: "BHIM",         type: "UPI • Cashback",         discount: 50 },
      { tag: null, icon: "💳", label: "₹20 off", sub: "Flipkart Axis",  type: "Credit Card • Cashback", discount: 20 },
      { tag: null, icon: "📱", label: "₹50 off", sub: "Paytm",          type: "UPI • Cashback",         discount: 50 },
      { tag: null, icon: "💳", label: "₹20 off", sub: "HDFC",           type: "Debit Card • Cashback",  discount: 20 },
    ]);
    console.log("✅ Default offers seeded");
  }
}
mongoose.connection.once("open", seedOffers);

app.get("/offers", async (req, res) => {
  try { res.json(await Offer.find({ active: true })); }
  catch { res.status(500).json({ error: "Failed to fetch offers" }); }
});

/* ═══════════════════════════════════
   📍 DELIVERY / PIN
   ═══════════════════════════════════ */
const pinData = {
  "411001": { city: "Pune", state: "Maharashtra" }, "422001": { city: "Nashik", state: "Maharashtra" },
  "400001": { city: "Mumbai", state: "Maharashtra" }, "110001": { city: "Delhi", state: "Delhi" },
  "560001": { city: "Bengaluru", state: "Karnataka" }, "600001": { city: "Chennai", state: "Tamil Nadu" },
  "500001": { city: "Hyderabad", state: "Telangana" }, "700001": { city: "Kolkata", state: "West Bengal" },
  "380001": { city: "Ahmedabad", state: "Gujarat" }, "302001": { city: "Jaipur", state: "Rajasthan" },
  "226001": { city: "Lucknow", state: "Uttar Pradesh" }, "800001": { city: "Patna", state: "Bihar" },
};

app.get("/delivery/:pincode", (req, res) => {
  const { pincode } = req.params;
  if (!/^\d{6}$/.test(pincode)) return res.status(400).json({ error: "Enter a valid 6-digit PIN code" });
  const location = pinData[pincode];
  if (!location) return res.status(404).json({ error: "Sorry, we don't deliver to this PIN code yet" });
  const d = new Date(); d.setDate(d.getDate() + 3);
  const formatted = d.toLocaleDateString("en-IN", { weekday: "short", day: "numeric", month: "short" });
  res.json({ pincode, city: location.city, state: location.state, deliveryDate: formatted, cod: true, freeDelivery: true, seller: "NKRFASHIONS", sellerRating: "3.9" });
});

app.listen(process.env.PORT || 5000, () =>
  console.log(`🚀 Server running on port ${process.env.PORT || 5000}`)
);