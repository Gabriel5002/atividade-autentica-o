require('dotenv').config();

const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');

const app = express();

// 🔹 Simulação de "banco"
const users = [];

// 🔹 Configuração OAuth Google
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
},
(accessToken, refreshToken, profile, done) => {

  const email = profile.emails[0].value;

  // 🔒 Restrição por domínio
  if (!email.endsWith("@ifc.edu.br")) {
    return done(null, false, { message: "Domínio não permitido" });
  }

  // 🔹 Verifica se já existe
  let user = users.find(u => u.googleId === profile.id);

  if (!user) {
    user = {
      googleId: profile.id,
      name: profile.displayName,
      email: email
    };
    users.push(user);
  }

  return done(null, user);
}
));

app.use(passport.initialize());

// 🔹 Rota inicial
app.get('/', (req, res) => {
  res.send('<a href="/auth/google">Login com Google</a>');
});

// 🔹 Login
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 🔹 Callback
app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/' }),
  (req, res) => {

    // 🔑 Gerar JWT
    const token = jwt.sign(req.user, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.send(`
      <h2>Login realizado</h2>
      <p>Token JWT:</p>
      <textarea rows="10" cols="50">${token}</textarea>
      <br/>
      <a href="/protected?token=${token}">Ir para área protegida</a>
    `);
  }
);

// 🔒 Middleware JWT
function authenticateJWT(req, res, next) {
  const token = req.query.token;

  if (!token) return res.send("Token não fornecido");

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.send("Token inválido");

    req.user = user;
    next();
  });
}

// 🔹 Área protegida
app.get('/protected', authenticateJWT, (req, res) => {
  res.send(`
    <h1>Área Protegida</h1>
    <p>Nome: ${req.user.name}</p>
    <p>Email: ${req.user.email}</p>
  `);
});

// 🔹 Lista de usuários (extra)
app.get('/users', (req, res) => {
  res.json(users);
});

app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});