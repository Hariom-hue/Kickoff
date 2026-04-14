require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt   = require("bcrypt");

const adminSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true },
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  role:      { type: String, default: "superadmin" },
  active:    { type: Boolean, default: true },
  lastLogin: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
});
const Admin = mongoose.model("Admin", adminSchema);

async function seed() {
  try {
    const uri = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/kickoffDB";
    await mongoose.connect(uri);
    console.log("✅ MongoDB Connected");

    await Admin.deleteMany({});
    console.log("🗑️  Cleared old admin records");

    const username = process.env.ADMIN_USERNAME || "kickoff";
    const password = process.env.ADMIN_PASSWORD || "kickoff.com1212";
    const email    = process.env.ADMIN_EMAIL    || "ombggaikwad@gmail.com";

    const hashed = await bcrypt.hash(password, 12);
    await Admin.create({
      username: username.toLowerCase(),
      email,
      password: hashed,
      role: "superadmin",
      active: true
    });

    console.log("✅ Admin created successfully!");
    console.log(`   Username : ${username}`);
    console.log(`   Password : ${password}`);
    console.log(`   Email    : ${email}`);

  } catch (err) {
    console.error("❌ Error:", err.message);
  }
  await mongoose.disconnect();
  process.exit(0);
}

seed();