const express = require("express");
const session = require("express-session");
const passport = require("passport");
const Local = require("passport-local").Strategy;

const app = express();

app.use(
  session({
    saveUninitialized: false,
    resave: false,
    secret: "1234",
  })
);

app.use(express.json()); // new
app.use(passport.initialize());
app.use(passport.session());

const db = {};

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser((email, done) => {
  done(null, db[email]); //findByEmail
});

// local strategy
passport.use(
  new Local(
    {
      passwordField: "password",
      usernameField: "email",
    },
    (email, password, done) => {
      if (!email || !password) {
        return done(null, false, { message: "Wrong creds" });
      }

      const userInDb = db[email]; //findByEmail
      if (!userInDb) {
        return done(null, false, { message: "Wrong creds" });
      }

      if (userInDb.password !== password) {
        return done(null, false, { message: "Wrong creds" });
      }

      done(null, userInDb);
    }
  )
);

app.post("/signup", (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Missing creds" });
  }

  if (db[email]) {
    return res.status(400).json({ message: "Email already exists" });
  }

  // save user
  db[email] = {
    email,
    password,
  };

  res.json({ ok: true });
});

app.post("/signin", (req, res, next) => {
  const doAuth = passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.json(info);
    }

    req.logIn(user, (loginErr) => {
      if (loginErr) {
        return next(err);
      }
      res.json(user);
    });
  });

  doAuth(req, res, next);
});

app.get("/profile", (req, res, next) => {
  if (!req.user) {
    return res.status(403).end();
  }
  res.json(req.user);
});

module.exports = app;

/*

Server                                     Client (chrome, ff)
1. Create a session with id         <---    Request
2. Handle the request
3. Send the response, with coockie
   Set-Cookie sid=ndsa;dsad         --->   Read Set-Cookie header
                                           Save cookie sid

1. Read the cookie                  <--- Request (with cookie)
2. Found sid (session id)
3. Read the session that has the id
4. handle the request

/api/signup <--- Registration (email, password)

/api/signin <--- Login (email, password)
                 User save to session

/api/profile <-- Private page (show if user is authenticated)
                 Check user is in the session

*/
