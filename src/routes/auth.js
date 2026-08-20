const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('../config/database');

const router = express.Router();

// Helper para codificación Base64URL requerida por PKCE (RFC 7636)
function base64UrlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Helper para verificar el code_verifier contra el code_challenge
function verifyPKCE(codeVerifier, codeChallenge) {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  const computedChallenge = base64UrlEncode(hash);
  return computedChallenge === codeChallenge || codeVerifier === codeChallenge;
}

// 1. Registro de Clientes: POST /oauth/clients
router.post('/clients', (req, res) => {
  const { client_name, client_type, redirect_uri, scopes } = req.body;

  if (!client_name || !client_type || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Faltan campos obligatorios' });
  }

  const clientId = crypto.randomBytes(8).toString('hex');
  let clientSecret = null;
  let clientSecretHash = null;

  if (client_type === 'confidential') {
    clientSecret = crypto.randomBytes(16).toString('hex');
    clientSecretHash = bcrypt.hashSync(clientSecret, 10);
  }

  const query = `
    INSERT INTO clients (client_id, client_secret_hash, client_type, redirect_uri, scopes)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.run(query, [clientId, clientSecretHash, client_type, redirect_uri, scopes || 'read'], function (err) {
    if (err) {
      return res.status(500).json({ error: 'server_error', error_description: err.message });
    }

    res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret, // Solo se muestra una vez al registrarse
      client_type,
      redirect_uri,
      scopes: scopes || 'read'
    });
  });
});

// 2. Pantalla de Autorización y PKCE: GET /oauth/authorize
router.get('/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, user_id } = req.query;

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  if (code_challenge_method !== 'S256' || !code_challenge) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Se requiere PKCE con metodo S256' });
  }

  db.get('SELECT * FROM clients WHERE client_id = ?', [client_id], (err, client) => {
    if (err || !client) {
      return res.status(400).json({ error: 'invalid_client' });
    }

    if (client.redirect_uri !== redirect_uri) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri no coincide' });
    }

    const code = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 120000; // Expira en 120 segundos (2 minutos)
    const mockUserId = user_id || 1; // Usuario autenticado

    const insertCodeQuery = `
      INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.run(insertCodeQuery, [code, client_id, mockUserId, redirect_uri, scope || client.scopes, code_challenge, code_challenge_method, expiresAt], (err) => {
      if (err) {
        return res.status(500).json({ error: 'server_error' });
      }

      // Redirecciona al cliente con el código emitido
      const redirectUrl = `${redirect_uri}?code=${code}&state=${state || ''}`;
      return res.status(200).json({ message: 'Redirigiendo...', redirect_url: redirectUrl, code });
    });
  });
});

// 3. Intercambio de Token (Soporta Authorization Code PKCE, Client Credentials y ROPC): POST /oauth/token
router.post('/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier, username, password, scope } = req.body;

  const jwtSecret = process.env.JWT_SECRET || 'super_secret_key_change_in_production';
  const issuer = process.env.JWT_ISSUER || 'https://auth.soundaccess.local';
  const audience = process.env.JWT_AUDIENCE || 'https://api.soundaccess.local';

  // FLUJO 1: Authorization Code + PKCE
  if (grant_type === 'authorization_code') {
    if (!code || !code_verifier) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Falta code o code_verifier' });
    }

    db.get('SELECT * FROM authorization_codes WHERE code = ?', [code], (err, authCode) => {
      if (err || !authCode) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Codigo invalido' });
      }

      if (authCode.used === 1) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Codigo ya utilizado' });
      }

      if (Date.now() > authCode.expires_at) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Codigo expirado' });
      }

      // Validacion PKCE
      const isValidPKCE = verifyPKCE(code_verifier, authCode.code_challenge);
      if (!isValidPKCE) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier invalido' });
      }

      // Marcar código como usado (Uso único)
      db.run('UPDATE authorization_codes SET used = 1 WHERE code = ?', [code]);

      const tokenPayload = {
        iss: issuer,
        sub: String(authCode.user_id),
        aud: audience,
        client_id: authCode.client_id,
        scope: authCode.scope,
        jti: crypto.randomUUID()
      };

      const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '15m' });
      return res.json({ access_token: token, token_type: 'Bearer', expires_in: 900 });
    });

  // FLUJO 2: Client Credentials (Servicio a Servicio)
  } else if (grant_type === 'client_credentials') {
    db.get('SELECT * FROM clients WHERE client_id = ?', [client_id], (err, client) => {
      if (err || !client || client.client_type !== 'confidential') {
        return res.status(401).json({ error: 'invalid_client' });
      }

      const isValidSecret = bcrypt.compareSync(client_secret || '', client.client_secret_hash || '');
      if (!isValidSecret) {
        return res.status(401).json({ error: 'invalid_client', error_description: 'Secret incorrecto' });
      }

      const tokenPayload = {
        iss: issuer,
        sub: `client:${client_id}`,
        aud: audience,
        client_id: client_id,
        scope: scope || client.scopes,
        jti: crypto.randomUUID()
      };

      const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '15m' });
      return res.json({ access_token: token, token_type: 'Bearer', expires_in: 900 });
    });

  // FLUJO 3: Resource Owner Password Credentials (ROPC Legado)
  } else if (grant_type === 'password') {
    console.warn('\x1b[33m%s\x1b[0m', '[SECURITY WARNING]: Flujo ROPC invocado. Desaconsejado segun RFC 9700.');

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
      if (err || !user) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Credenciales invalidas' });
      }

      const isValidPassword = bcrypt.compareSync(password || '', user.password_hash);
      if (!isValidPassword) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Credenciales invalidas' });
      }

      const tokenPayload = {
        iss: issuer,
        sub: String(user.id),
        aud: audience,
        client_id: client_id || 'direct-access',
        scope: scope || 'read write',
        jti: crypto.randomUUID()
      };

      const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '15m' });
      return res.json({ access_token: token, token_type: 'Bearer', expires_in: 900 });
    });

  } else {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

module.exports = router;