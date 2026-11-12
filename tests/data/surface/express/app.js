const express = require('express');
const { requireAuth } = require('./middleware/auth');
const users = require('./routes/users');
const admin = require('./routes/admin');
const app = express();

app.use(express.json());
app.get('/health', (req, res) => res.send('ok'));
app.use('/api/users', users);
app.use('/api/admin', requireAuth, admin);

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  res.json({ user: username, ok: password.length > 0 });
});

app.listen(3000);
