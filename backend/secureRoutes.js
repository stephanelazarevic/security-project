const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

module.exports = (secret, usersCollection) => {
  // Login sécurisé
  router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (typeof username !== "string" || typeof password !== "string") {
      // continue jusqu’à la recherche (et échoue naturellement)
      return res.status(401).json({ msg: "Invalid credentials" });
    }

    const user = await usersCollection.findOne({ username, password });
    if (user) {
      const token = jwt.sign({ username: user.username, role: user.role }, secret, { expiresIn: '1h' });
      return res.json({ token });
    }

    res.status(401).json({ msg: "Invalid credentials" });
  });

  // LFI sécurisé
  router.get('/read-file', (req, res) => {
    const file = req.query.file;
    if (!file || file.includes("..") || file.startsWith("/")) {
      return res.status(400).send("Invalid file path");
    }

    const filePath = path.join(__dirname, file);
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) return res.status(500).send("Error reading file");
      res.send(data);
    });
  });

  // JWT sécurisé
  router.get('/profile', (req, res) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).send("No token");

    const token = auth.split(" ")[1];
    jwt.verify(token, secret, (err, decoded) => {
      if (err) return res.status(401).send("Invalid token");
      res.json({ message: `Welcome ${decoded.username}`, role: decoded.role });
    });
  });

  return router;
};
