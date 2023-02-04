require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require('passport-google-oauth20').Strategy;


const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String
});

const secretSchema = new mongoose.Schema({
    secret: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

mongoose.set('strictQuery', true);

mongoose.connect("mongodb://127.0.0.1:27017/secretUsersDB");

const User = new mongoose.model("User", userSchema);
const Secret = new mongoose.model("Secret", secretSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, {
            id: user.id,
            username: user.username,
            name: user.name
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile']
    }));

app.get('/auth/google/secrets',
    passport.authenticate('google', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        res.redirect('/secrets');
    });

app.listen(3000, () => {
    console.log("Listening on Port 3000.");
});

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        Secret.find({}, (err, docs) => {
            if(err){
                console.log(err);
            }
            else {
                res.render("secrets", {renderSecrets: docs});
            }
        })
    } else {
        res.redirect("/login")
    }
})

app.route("/login")
    .get((req, res) => {
        res.render("login");
    })
    .post(passport.authenticate("local"), function (req, res) {
        res.redirect("/secrets");
    });

app.route("/register")
    .get((req, res) => {
        res.render("register");
    })
    .post((req, res) => {
        User.register({
            username: req.body.username
        }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register")
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets")
                })
            }
        })
    });

app.route("/submit")
    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.render("submit")
        } else {
            res.redirect("/login")
        }
    })
    .post((req, res) => {
        const secret = req.body.secret;
        const dbSecret = new Secret({secret: secret});
        dbSecret.save((err, result) => {
            if(err) {
                console.log(err);
            }
            else {
                res.redirect("/secrets");
            }
        });
    });

app.get('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/")
        }
    });
});