//jshint esversion:6
require("dotenv").config()
const express = require("express");
const bodyParser =  require("body-parser");
const ejs= require("ejs");
const mongoose= require("mongoose");
const session = require("express-session");
const passport= require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app= express();

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.URL, {useNewUrlParser: true , useUnifiedTopology: true,useFindAndModify: false});
mongoose.set("useCreateIndex",true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: [{
        content : String,
        category : String
    }]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id); 
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-tt.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get("/",function (req,res) {
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
});

app.get("/login",function (req,res) {
    res.render("login");
});

app.get("/register",function (req,res) {
    res.render("register",{message: ""});
});

app.get("/logout", function (req,res) {
    req.logout();
    res.redirect("/");
})

app.get("/submit", function (req,res) {
    if (req.isAuthenticated()){
        res.render("submit");
    } else{
        res.redirect("/login");
    }
});

app.get("/secrets", function (req,res) {
    if (req.isAuthenticated()){
        User.find({"secret": {$ne: null} }, function (err, foundUsers) {
            if(err){
                console.log(err);
            } else{
                if(foundUsers){
                    res.render("secrets", { usersWithSecrets: foundUsers });
                }
            }
        })
    } else{
        res.redirect("/login");
    }
});
app.get("/category", function (req,res) {
    if (req.isAuthenticated()){
        res.render("category",{usersWithSecrets: null});
    } else{
        res.redirect("/login");
    }
});
app.post("/category", function (req,res) {
    if (req.isAuthenticated()){
        var reqCat = req.body.category;
        if(reqCat === undefined || reqCat === null)
            reqCat = "General";
        User.find({"secret.category":  reqCat }, function (err, foundUsers) {
            if(err){
                console.log(err);
            } else{
                if(foundUsers){
                    res.render("category", { usersWithSecrets: foundUsers, reqCategory: reqCat });
                }
            }
        })
    } else{
        res.redirect("/login");
    }
});

app.post("/submit", function (req,res) {
    const submittedSecret = {content :req.body.content,
        category:  req.body.category};
    User.findById(req.user.id, function (err,foundUser) {
        if(err){
            console.log(err);
        } else {
            if(foundUser){
                foundUser.secret.push(submittedSecret);
                foundUser.save(function () {
                    res.redirect("/secrets")
                });
            }
        }
    })
})

app.post("/register",function (req,res) {
    User.register({username: req.body.username}, req.body.password, function (err,user) {
        if(err){
            res.render("register",{message: "Already a member!"});
        } else{
            passport.authenticate("local")(req,res,function () {
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/login",function (req,res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user,function (err) {
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local",{ failureRedirect: "/login" })(req,res,function () {
                res.redirect("/secrets");
            });
        }
    })
});

app.listen(process.env.PORT || 3000,function () {
    console.log("Server is running ...");
})