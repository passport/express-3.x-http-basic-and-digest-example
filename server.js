var express = require('express');
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;
var DigestStrategy = require('passport-http').DigestStrategy;
var db = require('./db');


// Configure the Basic strategy for use by Passport.
//
// The Basic strategy requires a `verify` function which receives the
// credentials (`username` and `password`) contained in the request.  The
// function must verify that the password is correct and then invoke `cb` with
// a user object, which will be set at `req.user` in route handlers after
// authentication.
passport.use(new BasicStrategy(
  function(username, password, cb) {
    db.users.findByUsername(username, function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      if (user.password != password) { return cb(null, false); }
      return cb(null, user);
    });
  }));
  
// Configure the Digest strategy for use by Passport.
//
// The Digest strategy requires a `secret`function, which is used to look up
// user.  The function must invoke `cb` with the user object as well as the
// user's password as known by the server.  The password is used to compute a
// hash, and authentication will fail if the computed value does not match that
// of the request.  The user object will be set at `req.user` in route handlers
// after authentication.
passport.use(new DigestStrategy({ qop: 'auth' },
  function(username, cb) {
    db.users.findByUsername(username, function(err, user) {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      return cb(null, user, user.password);
    })
  }));


// Create a new Express application.
var app = express();

// Configure Express application.
app.configure(function() {
  app.use(express.logger());
});

// curl -v --user jack:secret --basic http://127.0.0.1:3000/
// curl -v --user jack:secret --digest http://127.0.0.1:3000/
// curl -v --user jack:secret --anyauth http://127.0.0.1:3000/
app.get('/',
  passport.authenticate(['basic', 'digest'], { session: false }),
  function(req, res) {
    res.json({ username: req.user.username, email: req.user.emails[0].value });
  });

app.listen(3000);
