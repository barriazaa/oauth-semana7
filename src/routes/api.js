const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const router = express.Router();

// 1. Obtener perfil del usuario autenticado (Prueba A3 / B1)
router.get('/me', authenticateToken(), (req, res) => {
  res.json({
    message: 'Perfil accedido exitosamente',
    user_id: req.user.sub,
    client_id: req.user.client_id,
    scope: req.user.scope
  });
});

// 2. Obtener canciones / playlists (Requiere scope 'read')
router.get('/playlists', authenticateToken('read'), (req, res) => {
  res.json({
    playlists: [
      { id: 1, title: 'Rock Clasico', owner_id: req.user.sub },
      { id: 2, title: 'Lo-Fi Beats', owner_id: req.user.sub }
    ]
  });
});

// 3. Crear nueva playlist (Requiere scope 'playlist:write' - Para Prueba B5)
router.post('/playlists', authenticateToken('playlist:write'), (req, res) => {
  const { name } = req.body;
  res.status(201).json({
    message: 'Playlist creada exitosamente',
    playlist: { id: Date.now(), name, owner_id: req.user.sub }
  });
});

module.exports = router;