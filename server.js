const express = require('express');
const app = express();

const { pool } = require("./dbConfig");
const  bcrypt = require('bcrypt');

const session = require('express-session');
const flash = require('express-flash');

const passport = require("passport");
const initializePassport = require("./passportConfig");

const cors = require("cors");

const bodyParser = require('body-parser');
const cookieParser = require("cookie-parser");

require("dotenv").config();

initializePassport(passport);

const PORT = process.env.PORT || 4000;

// Middleware

// Parses details from a form

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));

app.use(session({
    key: "userID",
    secret: "secret",
    resave: false, 
    saveUninitialized: false,
    cookie: {
        expires: 60*60*24,
    }
}))

// Funtion inside passport which initializes passport
app.use(passport.initialize());
// Store our variables to be persisted across the whole session. Works with app.use(Session) above
app.use(passport.session());
app.use(flash());

app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true}));

app.use(express.json());




app.get('/', (req, res) => {
    res.render("index");
});

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render("register");
});

app.get('/users/login', checkAuthenticated, (req, res) => {
    res.render("login");
});

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
    res.render("dashboard", {user: req.user.name});
});

app.get("/users/logout", (req, res) => {
    req.logout();
    res.render("login", { message: "You have logged out successfully" });
});

app.post("/users/register", async (req, res) => {
    let { name, email, password, password2 } = req.body;
    
    console.log({
        name, email, password, password2
    })

    let errors = [];

    if (!name || !email || !password || !password2){
        errors.push({message: "All fields are required"});
    }
    if (password.length<6){
        errors.push({message: "Password should be between 6 to 18 characters"});
    }
    if (password != password2){
        errors.push({message: "Password does not match"});
    }
    if(errors.length>0){
        res.render("register", {errors});
    }else{
        //form validation passed

        let hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        pool.query(
            `select * from users where email = $1`, [email], (err, results) => {
                if (err) {
                    throw err;
                }

                console.log(results.rows);
                if (results.rows.length > 0){
                    errors.push({message: "Email already registerd"});
                    res.render("register", {errors});
                } else {
                    pool.query(
                        `insert into users (name,email,password) values ($1, $2, $3) returning id, password`, [name, email, hashedPassword], (err, results) => {
                            if (err) {
                                throw err;
                            }

                            console.log(results.rows);
                            req.flash('success_msg', "you are now registerd, please login.");
                            res.redirect('/users/login/');
                        }
                    )
                }
            }
        )
    }
});

app.post("/users/login", passport.authenticate('local', {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
}));

function checkAuthenticated(req,res, next){
    if (req.isAuthenticated()){
        return res.redirect("/users/dashboard");
    }
    next();
}

function checkNotAuthenticated(req,res,next){
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect("/users/login");
}


app.listen(PORT, () => {
    console.log(`Server runing on port ${PORT}`);
});

//***


//new stuff

// app.use(function(req, res, next) {
//     res.header("Access-Control-Allow-Origin", "*");
//     res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
//     next();
//   });


app.post("/register", async (req,res) =>{
    let { name, email, password, password2 } = req.body;
    let errors=[];
    
    console.log({
        name, email, password, password2
    })
    //form validation passed
    let hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);

    pool.query(
        `select * from users where email = $1`, [email], (err, results) => {
            if (err) {
                    throw err;
                }
                console.log(results.rows);
                if (results.rows.length > 0){
                    // res.status(500);
                    res.json({message: "Email already registerd"});
                } else {
                    pool.query(
                        `insert into users (name,email,password) values ($1, $2, $3) returning id, password`, [name, email, hashedPassword], (err, results) => {
                            if (err) {
                                throw err;
                            }

                            console.log(results.rows);

                            req.flash('success_msg', "you are now registerd, please login.");
                            // res.status(200);
                            res.json({message: "Account successfully registered"});
                        }
                    )
                }
            }
        )
});

// app.post("/signin", passport.authenticate('local', {
//     successRedirect: "/",
//     failureRedirect: "/signin",
//     failureFlash: true
// }));

app.post("/signin", async (req,res) =>{
    let {email, password} = req.body;
    let errors=[];
    
    console.log({
        email, password
    })

    //form validation passed
    pool.query(
        `Select * from users where email = $1`, [email], (err, results) => {
            if (err) {
                throw err;
            }

            console.log(results.rows);

            if (results.rows.length>0) {
                const user = results.rows[0];
                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if (err) {
                        throw err;
                    }
                    if (isMatch){
                        req.session.user = results;
                        console.log(req.session.user);
                        res.send(results.rows); 
                    } else {
                        res.json({message: "Password is not correct"})
                    }
                });
            } else {
                res.json({message: "Email not registered"});
            }
        }
    );
});

app.get("/signin", (req,res)=>{
    if (req.session.user){
        res.send({loggedIn: true, user: req.session.user});
    } else {
        res.send({loggedIn: false});
    }
})

app.get("/logout", (req,res)=>{
    if (req.session.user){
        req.session.destroy;
        res.send({loggedIn: false});
    } else {
        res.send({loggedIn: false});
    }
})