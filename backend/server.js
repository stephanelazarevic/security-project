const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const cors = require('cors');

const secureRoutesFactory = require('./secureRoutes'); // routes sécurisées

const app = express();
app.use(cors());
app.use(bodyParser.json());

const INSECURE_SECRET = "insecure-secret";
const SECURE_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(64).toString('hex');
const mongoUrl = "mongodb://mongodb:27017";
let users;

MongoClient.connect(mongoUrl).then(client => {
    const db = client.db("vulndb");
    users = db.collection("users");

    users.deleteMany({});
    users.insertMany([
        { username: "admin", password: "admin123", role: "admin" },
        { username: "victim", password: "anything", role: "user" }
    ]);

    // 🐱‍👤 Routes vulnérables
    app.post('/api/login', async (req, res) => {
        let { username, password } = req.body;
        try { username = JSON.parse(username); } catch (_) {}
        const user = await users.findOne({ username, password });
        if (user) {
            const token = jwt.sign({ username: user.username, role: user.role }, INSECURE_SECRET);
            return res.json({ token });
        }
        res.status(401).json({ msg: "Invalid credentials" });
    });

    app.get('/api/read-file', (req, res) => {
        const file = req.query.file;
        const filePath = path.join(__dirname, file);
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) return res.status(500).send("Error reading file");
            res.send(data);
        });
    });

    app.get('/api/profile', (req, res) => {
        const auth = req.headers.authorization;
        if (!auth) return res.status(401).send("No token");
        try {
            const token = auth.split(" ")[1];
            const decoded = jwt.decode(token);
            res.json({ message: `Welcome ${decoded.username}`, role: decoded.role });
        } catch (e) {
            res.status(401).send("Invalid token");
        }
    });

    // 🛡️ Routes sécurisées
    app.use('/secure-api', secureRoutesFactory(SECURE_SECRET, users));
});

app.listen(3000, () => console.log("Backend listening on port 3000"));
module.exports = app; // Export the app for testing