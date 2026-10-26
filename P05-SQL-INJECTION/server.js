
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const {scryptSync, randomBytes, timingSafeEqual} = require("crypto");
const salt = randomBytes(16).toString("hex");
const hash = scryptSync("12345", salt, 64).toString("hex");
const app = express();
const db = new sqlite3.Database(path.join(__dirname, "usuarios.db"));

app.use(express.json());

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  // Credenciales ficticias, solo para la práctica
  db.run(
    `INSERT OR IGNORE INTO usuarios
     (username, password) VALUES (?, ?)`,
    ["admin", salt + ":" + hash]
  );
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

// Ejemplo protegido
app.post("/login", (req, res) => {
  const { usuario, password } = req.body || {};

  if (typeof usuario !== "string" ||
      typeof password !== "string" || usuario.length > 200 || password.length > 200) {
    return res.status(400).json({mensaje: "Datos inválidos"});
  }

  db.get(
    `SELECT * FROM usuarios
     WHERE username = ?`,
    [usuario],
    (err, fila) => {
      if (err) {
        return res.status(500).json({mensaje: "Error interno"});
      }

      let valido = false;
      if (fila) { const [s,h] = fila.password.split(":"); valido = timingSafeEqual(scryptSync(password,s,64),Buffer.from(h,"hex")); }
      res.json({
        mensaje: valido ? "Acceso concedido" : "Acceso denegado"
      });
    }
  );
});

// Solo disponible en esta computadora
app.listen(3102, "127.0.0.1", () => {
  console.log("Servidor: http://127.0.0.1:3102");
});
    