const express  = require('express'); 
const passport = require('passport'); 
const LdapStrategy = require('passport-ldapauth'); 
PORT = 3000
const app = express(); 
const fs = require('fs');

app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: false })); 

app.use(require('express-session')({ 
  secret: '{secret}', 
  resave: false, 
  saveUninitialized: false,
  cookie: {
    sameSite: 'strict',
    maxAge: 28800000,
    secure: true,
    httpOnly: true
  }
}));

app.use((req, res, next) => { 
    res.setHeader('Strict-Transport-Security', 'max-age=63072000');
    res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self';");
  next(); 
  });

app.use(passport.initialize()); 
app.use(passport.session());

passport.use(new LdapStrategy({ 
    server: { 
        url: 'ldaps://{link}:636', 
        bindDN: '{bind_dn}', 
        bindCredentials: '{password}', 
        searchBase: '{search}', 
        searchFilter: '(uid={{username}})', 
        tlsOptions: {
            ca: [
                fs.readFileSync('{ldap_cert_location}', 'utf-8')
            ]
        },
    }, 
}));

passport.serializeUser((user, done) => done(null, user.uid)); 
passport.deserializeUser((id, done) => done(null, { uid: id })); 

app.get('/login', (req, res) => { 
  res.send(`
    <form method="POST"> 
      <input name="username" placeholder="username"/> 
      <input name="password" type="password" placeholder="password"/> 
      <button type="submit">Log in with LDAP</button> 
    </form>`); 
}); 

app.post('/login', 
    passport.authenticate('ldapauth', { 
        successRedirect: '/', 
        failureRedirect: '/login',
    })
);

app.get('/', (req, res) => { 
  if (req.isAuthenticated()){
    console.log(req);
    res.send(`<h1>Welcome, ${req.user.uid}!</h1><form action="/logout" method="POST"><button>Logout</button></form>`); 
  } else {
    res.send(`<form action="/login" method="GET"><button>Login</button></form>`);
  }
}); 

app.post('/logout', (req, res) => {
    req.logout(() => {
      res.redirect('/');
    });
});

app.use((req, res) => { 
    res.status(404);
    res.send('Not found'); 
  });

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`)
});