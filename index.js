const express = require('express')
const logger = require('morgan')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8 = 256 random bits
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')

// PORT where the express server will listen to
const port = 3000

const app = express()

// Middleware that allows us to log each request that arrives to the server
app.use(logger('dev'))

/* DATABASE SETUP */
// Create database file or get existing one 
const db = new sqlite3.Database('database')

// Create users table
db.run("CREATE TABLE users (username VARCHAR, password VARCHAR)",
    function(err){
        if(err){
            // The table was already created -> Clear the table
            console.info("[INFO] Clearing users table...")
            db.run("DELETE FROM users", function(err){
                if(err){
                    console.log(err)
                }
            })
        }
    }
)

// Insert default user ('walrus', 'walrus')
bcrypt.hash('walrus', 10, function(err, hashedPassword){
    if(err){
        throw err
    }
    // Insert into database default user
    db.run("INSERT INTO users (username, password) VALUES ($name, $password)", {
        $name: 'walrus',
        $password: hashedPassword 
    }, function(err){
        if(err){
            console.log(err)
        }
        console.info("[INFO] Inserting default user into database...")
        db.all("SELECT username, password FROM users", function(err, rows){
            if(err){
                console.log(err)
            }
            console.log(rows)
        })
    })
})

/* PASSPORT SETUP */
// Define the method that will be used to extract the JWT token
const cookieExtractor = req => {
    console.log("[INFO] Parsing cookie...")
    let jwt = null 

    if (req && req.cookies) {
        jwt = req.cookies['jwt']
    }
    if(jwt==null){
        console.log("[ERROR] User is not logged in")
    }
    return jwt
}

// Define local strategy
passport.use('local', new LocalStrategy({
        usernameField : 'username',
        passwordField : 'password',
        session: false },
    function (username, password, done){
        db.get("SELECT password FROM users WHERE username = $username", {
            $username : username
        }, function(err, row){
            if(err){
                console.log("[ERROR] while retrieving the user from the db")
                console.log(err)
                return done(null, false)
            }
            try{
                let hashedPassword = row.password
                console.log("[INFO] User found on the database! ")
                console.log("[INFO] Comparing hashed passwords")
                bcrypt.compare(password, hashedPassword, (err, same) => {
                    if(err){
                        console.log("[ERROR] While comparing the passwords")
                        return done(null, false)
                    }
                    if(!same){
                        console.log("[INFO] Wrong password!")
                        return done(null, false)
                    }
                    console.log("[INFO] Correct password!")
                    const user = {
                        username: username
                    }
                    return done(null, user)
                })
            }catch{
                console.log("[INFO] User not found in the database")
                return done(null, false);
            }
        })
    }
))

// Define JWT Strategy
passport.use('jwt', new JwtStrategy({
    jwtFromRequest: cookieExtractor,
    secretOrKey: jwtSecret
    },
    function (jwt_payload, done){
        // Check if user exists in the database
        db.get("SELECT username FROM users WHERE username = $username",{
            $username: jwt_payload.sub
        }, function(err, row){
            if(err){
                console.log("[ERROR] An error occurred while searching for the user in the database")
                return done(null, false)
            }
            try{
                let username = row.username
                console.log("[INFO] User is logged correctly")
                const user = {
                    username: username,
                }
                return done(null, user)
            }catch{
                console.log("[INFO] User in the JWT not found in the database...suspicius")
                return done(null, false)
            }
        })
    }
))

// Requirement of passport local strategy
app.use(express.urlencoded({extended: true}))

// Load passport auth middleware
app.use(passport.initialize())

// Load cookie parser 
app.use(cookieParser())


/* ROUTES CONFIGURATION */

// GET / (main route)
// The user should be authenticated to access to this route. If authentication is successful we show a fortune tell
app.get('/', passport.authenticate('jwt', {session: false, failureRedirect: '/login'}), (req, res) => {
        res.send(fortune.fortune());
    }
)

// GET /user (personal user page)
// User should be authenticated to access to this route. If authentication is successful we show the user username
app.get('/user', passport.authenticate('jwt', {session: false, failureRedirect: '/login'}), (req, res) => {
        res.send(req.user);
    }
)

// GET /login (login page)
// Returns the login html form
app.get('/login', (req, res) => {
    res.sendFile('login.html', {root: __dirname})
})

// POST /login (login page)
// We authenticate the user in the database. If the user didn't exist we create it
app.post('/login', passport.authenticate('local', {failureRedirect: '/wrong-login', session: false}), (req, res) => {
    console.log("[INFO] Creating the JWT token...")
    // Data to put inside the JWT 
    const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week
        // (7x24x60x60 = 604800s)
        role: 'user'
    }

    // Generate the signed json web token
    const token = jwt.sign(jwtClaims, jwtSecret)

    console.log("[INFO] JWT token created and sent succesfuly, " + 
    "redirecting to fortune page...")
    // Send the token directly to the browser
    // WE SET THE VALIDITY FOR 2 MIN
    // Use the following code instead if we want it valid until end of session
    //res.cookie('jwt', token, {httpOnly: true})
    res.cookie('jwt', token, {expires: new Date(Date.now() + 120 * 1000), httpOnly: true})
    res.redirect('/')
    
    console.log(`[INFO] Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`[INFO] Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
})

// GET /wrong-login
// We send the user to this page when it has introduced an invalid username or password
app.get('/wrong-login', (req, res) =>{
    res.sendFile('wrong-login.html', {root: __dirname})
})

// GET /logout (logout page)
// We logout the user by clearing up the cookie
app.get('/logout', (req, res) =>{
    res.clearCookie('jwt')
    res.send("User has been logged out")
})

// Default error handler.
app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
})

/* START SERVER */

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})
