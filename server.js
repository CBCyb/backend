const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();

// --- SECURITY LAYER 1: STRICT CORS ---
// In production, you will change '*' to your actual Vercel domain (e.g., 'https://my-pixel-talk.vercel.app')
// This prevents other websites from secretly connecting to your backend.
const allowedOrigins = process.env.FRONTEND_URL || '*';
app.use(cors({ origin: allowedOrigins, credentials: true }));

app.get('/', (req, res) => {
  res.send('Backend is running securely!');
});

const server = http.createServer(app);

const io = new Server(server, {
  cors: { 
    origin: allowedOrigins, 
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const rooms = {};

// --- SECURITY LAYER 2: IN-MEMORY RATE LIMITER ---
// Tracks how many times a user performs an action to prevent spam and brute-force attacks
const rateLimits = {}; 
const checkRateLimit = (socketId, action, limit, timeWindow) => {
  if (!rateLimits[socketId]) rateLimits[socketId] = {};
  if (!rateLimits[socketId][action]) rateLimits[socketId][action] = [];
  
  const now = Date.now();
  // Clear old timestamps outside the time window
  rateLimits[socketId][action] = rateLimits[socketId][action].filter(time => now - time < timeWindow);
  
  if (rateLimits[socketId][action].length >= limit) return false; // Block action
  
  rateLimits[socketId][action].push(now); // Allow action
  return true;
};

// --- SECURITY LAYER 3: INPUT SANITIZER ---
// Destroys malicious HTML tags so hackers cannot execute scripts in your chat
const sanitizeText = (str) => {
  if (typeof str !== 'string') return '';
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;").trim();
};


io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('check-room', (roomId, callback) => {
    const cleanRoomId = sanitizeText(roomId).substring(0, 50); // Prevent massive payloads
    const isLocked = rooms[cleanRoomId] && rooms[cleanRoomId].password ? true : false;
    callback(isLocked);
  });

  socket.on('join-room', (roomId, avatarSeed, nickname, password) => {
    
    // ANTI-BRUTE FORCE: Max 5 join attempts per minute per user
    if (!checkRateLimit(socket.id, 'join', 5, 60000)) {
      socket.emit('join-error', 'Too many login attempts. Please wait 60 seconds.');
      return;
    }

    // SANITIZATION & LIMITS: Cut off dangerously long names/IDs
    const cleanRoomId = sanitizeText(roomId).substring(0, 50);
    const cleanNickname = sanitizeText(nickname).substring(0, 20) || 'Anonymous';
    const cleanAvatarSeed = sanitizeText(avatarSeed).substring(0, 100);

    if (rooms[cleanRoomId]) {
      if (rooms[cleanRoomId].password && rooms[cleanRoomId].password !== password) {
        socket.emit('join-error', 'Incorrect room password.');
        return;
      }
    } else {
      rooms[cleanRoomId] = { users: {}, password: password || null };
    }

    socket.join(cleanRoomId);
    
    const isHost = Object.keys(rooms[cleanRoomId].users).length === 0;
    const role = isHost ? 'host' : 'participant';
    
    rooms[cleanRoomId].users[socket.id] = { role, avatarSeed: cleanAvatarSeed, nickname: cleanNickname };

    socket.emit('role-assigned', role);
    socket.to(cleanRoomId).emit('user-connected', socket.id, cleanAvatarSeed, cleanNickname);
    socket.emit('room-users', rooms[cleanRoomId].users);

    // WebRTC Signaling
    socket.on('offer', (id, message) => socket.to(id).emit('offer', socket.id, message));
    socket.on('answer', (id, message) => socket.to(id).emit('answer', socket.id, message));
    socket.on('ice-candidate', (id, message) => socket.to(id).emit('ice-candidate', socket.id, message));

    socket.on('chat-message', (text) => {
      // ANTI-SPAM: Max 5 chat messages per 5 seconds
      if (!checkRateLimit(socket.id, 'chat', 5, 5000)) return;

      // SANITIZATION: Strip scripts and enforce a strict 500 character limit per message
      const cleanText = sanitizeText(text).substring(0, 500);
      if (!cleanText) return;

      io.to(cleanRoomId).emit('new-message', { sender: cleanNickname, text: cleanText });
    });

    socket.on('kick-user', (targetSocketId) => {
      if (rooms[cleanRoomId] && rooms[cleanRoomId].users[socket.id]?.role === 'host') {
        io.to(targetSocketId).emit('kicked');
        const targetSocket = io.sockets.sockets.get(targetSocketId);
        if (targetSocket) targetSocket.disconnect();
      }
    });

    socket.on('force-mute', (targetSocketId) => {
      if (rooms[cleanRoomId] && rooms[cleanRoomId].users[socket.id]?.role === 'host') {
        io.to(targetSocketId).emit('muted-by-host');
      }
    });

    socket.on('disconnect', () => {
      console.log(`User disconnected: ${socket.id}`);
      if (rooms[cleanRoomId]) {
        delete rooms[cleanRoomId].users[socket.id];
        socket.to(cleanRoomId).emit('user-disconnected', socket.id);
        if (Object.keys(rooms[cleanRoomId].users).length === 0) delete rooms[cleanRoomId];
      }
      // CLEANUP: Free up server memory to prevent memory leaks
      delete rateLimits[socket.id]; 
    });
  });
});

const PORT = process.env.PORT || 3001;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Signaling server firmly running on port ${PORT}`);
}).on('error', (err) => {
  console.error('CRITICAL SERVER ERROR:', err);
});