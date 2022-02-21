const express = require("express");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const session = require("express-session");
const Local = require("passport-local").Strategy;

const app = express();

app.use(morgan("dev"));

const fakeDb = {};

app.use(
  session({
    resave: false,
    secret: "secret",
    saveUninitialized: false,
  })
);

app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.email);
});

passport.deserializeUser((email, done) => {
  done(null, fakeDb[email]);
});

passport.use(
  new Local(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (email, password, done) => {
      if (!email || !password) {
        return done(null, false, { message: "Missing credentials" });
      }

      const user = fakeDb[email];
      if (!user) {
        return done(null, false, { message: "Wrong credentials" });
      }

      bcrypt
        .compare(password, user.hash)
        .then((ok) => {
          if (!ok) {
            return done(null, false, { message: "Wrong credentials" });
          }
          return done(null, user);
        })
        .catch((err) => {
          done(err);
        });
    }
  )
);

const verify = (req, res, next) => {
  if (!req.user) {
    return res.status(400).end("Forbidden");
  }
  next();
};

app.post("/signup", (req, res, next) => {
  const {
    body: { email, password },
  } = req;

  if (!email || !password) {
    return res.status(403).json({ message: "Missing creds" });
  }

  if (fakeDb[email]) {
    return res.status(403).json({ message: "User already exists" });
  }

  bcrypt
    .hash(password, 10)
    .then((hash) => {
      fakeDb[email] = { email, hash, id: Date.now() };
      return res.json({ message: "User created" });
    })
    .catch((err) => {
      return next(err);
    });
});

app.post("/signin", passport.authenticate("local"), (req, res, next) => {
  res.json(req.user);
});

app.get("/profile", verify, (req, res, next) => {
  res.json(req.user);
});

module.exports = app;
