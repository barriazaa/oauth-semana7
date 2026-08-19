const jwt = require('jsonwebtoken');

// Middleware para validar JWT y verificar scopes requeridos
function authenticateToken(requiredScope = null) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extraer Bearer TOKEN

    if (!token) {
      return res.status(401).json({ error: 'unauthorized', error_description: 'Token no proporcionado' });
    }

    const jwtSecret = process.env.JWT_SECRET || 'super_secret_key_change_in_production';

    jwt.verify(token, jwtSecret, (err, user) => {
      if (err) {
        return res.status(401).json({ error: 'unauthorized', error_description: 'Token invalido o expirado' });
      }

      // Validar Emisor (iss) y Audiencia (aud)
      const expectedIssuer = process.env.JWT_ISSUER || 'https://auth.soundaccess.local';
      const expectedAudience = process.env.JWT_AUDIENCE || 'https://api.soundaccess.local';

      if (user.iss !== expectedIssuer || user.aud !== expectedAudience) {
        return res.status(401).json({ error: 'unauthorized', error_description: 'Emisor o audiencia invalidos' });
      }

      // Validar Scopes / Permisos si la ruta lo exige (Prueba B5)
      if (requiredScope) {
        const tokenScopes = user.scope ? user.scope.split(' ') : [];
        if (!tokenScopes.includes(requiredScope)) {
          return res.status(403).json({ error: 'forbidden', error_description: `Se requiere el scope: ${requiredScope}` });
        }
      }

      req.user = user;
      next();
    });
  };
}

module.exports = { authenticateToken };