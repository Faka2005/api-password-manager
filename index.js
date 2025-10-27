// 📦 Dépendances
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

// 🚀 Initialisation de l'app Express
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// 🌍 Connexion MongoDB
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db, usersCollection;

// --- Initialisation de la base de données ---
async function initDB() {
  try {
    await client.connect();
    db = client.db("PasswordManager");
    usersCollection = db.collection("user");
    passwordCollection = db.collection("password")
    console.log("✅ Connecté à MongoDB Atlas !");
  } catch (err) {
    console.error("❌ Erreur de connexion à MongoDB :", err);
  }
}

initDB();

// --- ROUTE : Enregistrement d’un utilisateur et d'un profil vide---
app.post("/register/user", async (req, res) => {
  const { firstName, lastName, email, password ,sexe} = req.body;

  if (!firstName || !lastName || !email || !password) {
    return res
      .status(400)
      .json({ message: "Tous les champs sont obligatoires" });
  }
  
  try {
    // Vérifie si l'utilisateur existe déjà
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email déjà utilisé" });
    }

    // Hash du mot de passe
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insertion dans la base
    const result = await usersCollection.insertOne({
      email,
      password: hashedPassword,
      createdAt: new Date(),
    });
    res.status(201).json({
      message: "Utilisateur enregistré avec succès ✅",
      userId: result.insertedId,
    });
  } catch (error) {
    console.error("Erreur dans /register/user :", error);
    res.status(500).json({ message: "Erreur lors de l’enregistrement" });
  }
});

// --- ROUTE : Connexion d’un utilisateur ---
app.post("/login/user", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email et mot de passe requis" });
  }

  try {
    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Utilisateur non trouvé" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Mot de passe incorrect" });
    }

    const profile = await profilesCollection.findOne({
      userId:  new ObjectId(user._id),
    });


    res.status(200).json({
      message: "Connexion réussie ✅",
      profile: profile,
    });
  } catch (error) {
    console.error("Erreur dans /login/user :", error);
    res.status(500).json({ message: "Erreur lors de la connexion" });
  }
});

// --- ROUTE : Modifie les informations d’un  utilisateur ---
app.put("/user/:id", async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  if (!id) {
    return res.status(400).json({ mesage: "Id requis" });
  }
  try {
    const result = await usersCollection.updateData(
      { userId: new ObjectId(id) },
      { $set: updateData }
    );
  } catch (error) {
    console.error("Erreur dans /user/:id :", error);
    res.status(500).json({ message: "Erreur lors de modification de profil" });
  }
});


// --- ROUTE : Renvoie tous les mots de passe d’un utilisateur ---
app.get("/user/password", async (req, res) => {
  try {
    // 🔹 On récupère l'ID utilisateur depuis les paramètres de requête
    const { userId } = req.body;

    // 🔹 Vérification des champs
    if (!userId) {
      return res.status(400).json({ message: "L'ID utilisateur est requis" });
    }

    // 🔹 Récupération de tous les mots de passe pour cet utilisateur
    const passwords = await passwordCollection
      .find({ userId: userId }) // stocké comme string dans ta route POST
      .toArray();

    // 🔹 Si aucun mot de passe trouvé
    if (!passwords.length) {
      return res
        .status(404)
        .json({ message: "Aucun mot de passe enregistré pour cet utilisateur." });
    }

    // 🔹 Réponse OK
    res.status(200).json({
      message: "Mots de passe récupérés avec succès ✅",
      count: passwords.length,
      data: passwords,
    });
  } catch (error) {
    console.error("Erreur dans /user/passwords :", error);
    res.status(500).json({ message: "Erreur serveur lors de la récupération" });
  }
});

// --- ROUTE : Ajoute un mot de passe à un utilisateur ---
app.post('/user/password', async (req, res) => {
  try {
    const { userId, email, password, site, description } = req.body;

    // ✅ Vérification des champs
    if (!userId || !email || !password || !site) {
      return res.status(400).json({ message: "Tous les champs sont requis" });
    }

    // ✅ Vérifie si ce site existe déjà pour cet utilisateur
    const existingPassword = await passwordCollection.findOne({ userId, site });
    if (existingPassword) {
      return res.status(400).json({ message: "Ce site est déjà enregistré pour cet utilisateur" });
    }

    // ✅ Hash du mot de passe
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // ✅ Insertion dans la base
    const result = await passwordCollection.insertOne({
      userId,
      email,
      password: hashedPassword,
      site,
      description: description || "",
      createdAt: new Date(),
    });

    // ✅ Réponse de succès
    res.status(201).json({
      message: "Mot de passe enregistré avec succès ✅",
      passwordId: result.insertedId,
    });

  } catch (error) {
    console.error("Erreur dans /user/password :", error);
    res.status(500).json({ message: "Erreur lors de l’enregistrement du mot de passe" });
  }
});


// --- ROUTE : Modifie un mot de passe à un utilisateur ---
app.put('/user/password/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { email, password, site, description } = req.body;

    // ✅ Vérification
    if (!id) {
      return res.status(400).json({ message: "L'ID du mot de passe est requis" });
    }

    if (!email && !password && !site && !description) {
      return res.status(400).json({ message: "Aucune donnée à mettre à jour" });
    }

    // ✅ Préparation des champs à mettre à jour
    const updateFields = {};
    if (email) updateFields.email = email;
    if (site) updateFields.site = site;
    if (description) updateFields.description = description;

    // ✅ Hash du mot de passe uniquement si fourni
    if (password) {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      updateFields.password = hashedPassword;
    }

    // ✅ Date de mise à jour
    updateFields.updatedAt = new Date();

    // ✅ Mise à jour dans MongoDB
    const result = await passwordCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Mot de passe non trouvé" });
    }

    if (result.modifiedCount === 0) {
      return res.status(200).json({ message: "Aucune modification effectuée (valeurs identiques)" });
    }

    res.status(200).json({
      message: "Mot de passe modifié avec succès ✅",
      modifiedCount: result.modifiedCount,
    });

  } catch (error) {
    console.error("Erreur dans /user/password/:id :", error);
    res.status(500).json({ message: "Erreur lors de la modification du mot de passe" });
  }
});



// --- ROUTE : Supprime un mot de passe à un utilisateur ---
app.delete('/user/password/:id', async (req, res) => {
  const { id } = req.params;

  // ✅ Vérification
  if (!id) {
    return res.status(400).json({ message: "L'ID du mot de passe est requis" });
  }

  try {
    // ✅ Suppression dans MongoDB
    const result = await passwordCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Mot de passe non trouvé ❌" });
    }

    // ✅ Réponse succès
    res.status(200).json({
      message: "Mot de passe supprimé avec succès ✅",
      deletedCount: result.deletedCount,
    });

  } catch (error) {
    console.error("Erreur dans /user/password/:id :", error);
    res.status(500).json({ message: "Erreur lors de la suppression du mot de passe" });
  }
});




// 🔌 Fermer proprement la connexion MongoDB si le serveur s'arrête
process.on("SIGINT", async () => {
  await client.close();
  console.log("🔌 Connexion MongoDB fermée");
  process.exit(0);
});

// 🚀 Lancement du serveur
app.listen(PORT, () =>
  console.log(`✅ Serveur démarré sur http://localhost:${PORT}`)
);

