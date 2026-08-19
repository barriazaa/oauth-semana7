const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// Crea el archivo database.db automáticamente en la raíz del proyecto
const dbPath = path.resolve(__dirname, '../../database.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // 1. Tabla de Usuarios
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

  // 2. Tabla de Clientes OAuth (Aplicaciones)
  db.run(`
    CREATE TABLE IF NOT EXISTS clients (
      client_id TEXT PRIMARY KEY,
      client_secret_hash TEXT,
      client_type TEXT CHECK(client_type IN ('public', 'confidential')) NOT NULL,
      redirect_uri TEXT NOT NULL,
      scopes TEXT NOT NULL
    )
  `);

  // 3. Tabla de Códigos de Autorización (Para flujo PKCE)
  db.run(`
    CREATE TABLE IF NOT EXISTS authorization_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      code_challenge_method TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0
    )
  `);

  // Inserta un usuario inicial para realizar tus pruebas en Postman
  db.get('SELECT COUNT(*) AS count FROM users', [], (err, row) => {
    if (row && row.count === 0) {
      const defaultPasswordHash = bcrypt.hashSync('Password123!', 10);
      db.run(
        'INSERT INTO users (username, password_hash) VALUES (?, ?)',
        ['usuario_prueba', defaultPasswordHash]
      );
    }
  });
});

module.exports = db;