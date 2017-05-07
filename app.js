var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var request = require("request");
var config = require('./config');
var user = require('./user');
var session = require('express-session');
var sys = require('util');
var index = require('./routes/index');
var users = require('./routes/users');
var app = express();
var passport = require('passport')
  , TwitterStrategy = require('passport-twitter').Strategy;
var oa = {};
var twitterAuthn = {};
var twitterAuthz = {};
var fs = require('fs');


function initTwitterOauth() {
  var OAuth= require('oauth').OAuth;
  oa = new OAuth("https://twitter.com/oauth/request_token",
                 "https://twitter.com/oauth/access_token",
                 config.consumerKey, config.consumerSecret,
                 "1.0A", "http://local.pd.com:3000/authn/twitter/callback", "HMAC-SHA1");
}

function uploadMedia(contents, cb) {
  oa.post(
    "https://upload.twitter.com/1.1/media/upload.json",
    user.token, user.tokenSecret,
    {"media_data": contents},
    cb
  );
}

function makeTweet(args, cb) {
  console.log(user.token, user.secret);
  console.log(args);
  oa.post(
    "https://api.twitter.com/1.1/statuses/update.json",
    user.token, user.tokenSecret,
    args,
    cb
  );
}

passport.serializeUser(function(_user, done) {
  user.id = Math.random().toString();
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    done(null, user);
});

twitterAuthn = new TwitterStrategy({
    consumerKey: config.consumerKey,
    consumerSecret: config.consumerSecret,
    callbackURL: "http://local.pd.com:3000/authn/twitter/callback"
  },
  function(token, tokenSecret, profile, done) {
    user.token = token;
    user.tokenSecret = tokenSecret;
    user.profile = profile;
    console.log("twitterAuthn");
    console.log("user.token", token);
    console.log("user.tokenSecret", tokenSecret);
    console.log("user.profile", profile);
    initTwitterOauth();
    done(null, user);
  });
twitterAuthn.name = 'twitterAuthn';

twitterAuthz = new TwitterStrategy({
    consumerKey: config.consumerKey,
    consumerSecret: config.consumerSecret,
    callbackURL: "http://local.pd.com:3000/authz/twitter/callback",
    userAuthorizationURL: "https://api.twitter.com/oauth/authorize"
  },
  function(token, tokenSecret, profile, done) {
    user.token = token;
    user.tokenSecret = tokenSecret;
    user.profile = profile;
    console.log("twitterAuthz");
    console.log("user.token", token);
    console.log("user.tokenSecret", tokenSecret);
    console.log("user.profile", profile);
    initTwitterOauth();
    done(null, user);
  });
twitterAuthz.name = 'twitterAuthz';

passport.use(twitterAuthn);
passport.use(twitterAuthz);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
app.use(favicon(path.join(__dirname, 'public','favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser("thissecretrocks"));
app.use(session({ secret: "blahhhhhhh" }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

//app.use('/', index);
app.use('/users', users);


app.get('/r/:subreddit?', function(req, res) {
  var subreddit= req.params.subreddit;
  request("http://www.reddit.com/r/"+subreddit+"/hot"+".json", function(error, response, body) {
    res.render('index', {title: 'Reddit', body: JSON.parse(body)})
  });
});

app.get('/subreddit/tweet',function(req,res) {
  var url= req.query.url;
  var text= req.query.text;

  request({"url":url, "encoding":'base64'}, function(error, response, body) {
    uploadMedia(body, function (error, data) {
      if(error) {
        console.log(require('util').inspect(error));
        res.end('bad stuff happened while uploading media');
      } else {
        console.log(data);
        var response_json = JSON.parse(data);
        console.log(response_json);
        makeTweet({"status": text, "media_ids": [response_json.media_id_string]}, function (error, data) {
          if(error) {
            console.log(require('util').inspect(error));
            res.end('bad stuff happened while updating status');
          } else {
            console.log(data);
            res.end('go check your tweets!');
          }
        });
      }
    });
  });

  // console.log(url,text)
  // makeTweet(text, function (error, data) {
  //   if(error) {
  //     console.log(require('util').inspect(error));
  //     res.end('bad stuff happened');
  //   } else {
  //     console.log(data);
  //     res.end('go check your tweets!');
  //   }
  // });
});

app.get('/authn/twitter', passport.authenticate('twitterAuthn'));

app.get('/authn/twitter/callback',
  passport.authenticate('twitterAuthn', { successRedirect: '/',
                                          failureRedirect: '/nfailure' }));

app.get('/authz/twitter', passport.authenticate('twitterAuthz'));

app.get('/authz/twitter/callback',
  passport.authenticate('twitterAuthz', { successRedirect: '/',
                                          failureRedirect: '/zfailure' }));

app.get('/twitter/tweet', function (req, res) {
  makeTweet(function (error, data) {
    if(error) {
      console.log(require('util').inspect(error));
      res.end('bad stuff happened');
    } else {
      console.log(data);
      res.end('go check your tweets!');
    }
  });
});

app.get('/', function(req, res) {
  res.send("Welcome to R World")
});

app.get('/upload/test', function(req, res) {
  fs.readFile('public/sample.jpg', 'base64', function(err, contents) {
      console.log(contents);

      uploadMedia(contents, function (error, data) {
        if(error) {
          console.log(require('util').inspect(error));
          res.end('bad stuff happened');
        } else {
          console.log(data);
          res.end('Media file uploaded!');
        }
      });
  });
});

initTwitterOauth();

app.listen (3000, function () {
  console.log("The application is running on local.pd.com:3000");
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
