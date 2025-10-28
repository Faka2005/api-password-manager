require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// --- MongoDB ---
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let db, usersCollection, passwordCollection;

async function initDB() {
  try {
    await client.connect();
    db = client.db("PasswordManager");
    usersCollection = db.collection("user");
    passwordCollection = db.collection("password");
    console.log("✅ Connecté à MongoDB Atlas !");
  } catch (err) {
    console.error("❌ Erreur MongoDB :", err);
  }
}
initDB();

// --- AES-256-GCM Encryption / Decryption ---
function encryptPassword(plainText) {
  const key = Buffer.from(process.env.ENCRYPTION_KEY, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext: encrypted.toString("base64"), iv: iv.toString("base64"), authTag: authTag.toString("base64") };
}

function decryptPassword({ ciphertext, iv, authTag }) {
  const key = Buffer.from(process.env.ENCRYPTION_KEY, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(authTag, "base64"));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64")), decipher.final()]);
  return decrypted.toString("utf8");
}

// ---------------------- USERS ----------------------
// Register
app.post("/register/user", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ message: "Tous les champs sont obligatoires" });

  try {
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email déjà utilisé" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await usersCollection.insertOne({ firstName, lastName, email, password: hashedPassword, createdAt: new Date() });
    res.status(201).json({ message: "Utilisateur enregistré ✅", userId: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Login
app.post("/login/user", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email et mot de passe requis" });

  try {
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Mot de passe incorrect" });

    res.status(200).json({ message: "Connexion réussie ✅", profile: user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ---------------------- PASSWORDS ----------------------

// Add password (AES)
app.post("/user/password", async (req, res) => {
  const { userId, site, email, password, description } = req.body;
  if (!userId || !site || !email || !password)
    return res.status(400).json({ message: "Tous les champs sont requis" });

  try {
    const existing = await passwordCollection.findOne({ userId, site });
    if (existing) return res.status(400).json({ message: "Ce site existe déjà" });

    const encrypted = encryptPassword(password);
    const result = await passwordCollection.insertOne({ userId, site, email, description: description || "", encrypted, createdAt: new Date() });

    res.status(201).json({ message: "Mot de passe enregistré ✅", passwordId: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Get passwords (decrypt)
app.get("/user/password/:userId", async (req, res) => {
  const { userId } = req.params;
  if (!userId) return res.status(400).json({ message: "ID requis" });

  try {
    const passwords = await passwordCollection.find({ userId }).toArray();
    const decrypted = passwords.map(p => ({
      _id: p._id,
      site: p.site,
      email: p.email,
      password: decryptPassword(p.encrypted),
      description: p.description,
    }));

    res.status(200).json({ message: "Mots de passe récupérés ✅", count: decrypted.length, data: decrypted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Update password
app.put("/user/password/:id", async (req, res) => {
  const { id } = req.params;
  const { site, email, password, description } = req.body;

  if (!id) return res.status(400).json({ message: "ID requis" });
  if (!site && !email && !password && !description) return res.status(400).json({ message: "Aucune donnée à mettre à jour" });

  try {
    const updateFields = {};
    if (site) updateFields.site = site;
    if (email) updateFields.email = email;
    if (description) updateFields.description = description;
    if (password) updateFields.encrypted = encryptPassword(password);

    const result = await passwordCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateFields });
    if (result.matchedCount === 0) return res.status(404).json({ message: "Mot de passe non trouvé" });

    res.status(200).json({ message: "Mot de passe modifié ✅" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Delete password
app.delete("/user/password/:id", async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: "ID requis" });

  try {
    const result = await passwordCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) return res.status(404).json({ message: "Mot de passe non trouvé" });
    res.status(200).json({ message: "Mot de passe supprimé ✅" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// ---------------------- Serveur ----------------------
process.on("SIGINT", async () => {
  await client.close();
  console.log("🔌 Connexion MongoDB fermée");
  process.exit(0);
});

app.listen(PORT, () => console.log(`✅ Serveur démarré sur http://localhost:${PORT}`));
