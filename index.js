const express = require('express')
const logger = require('morgan')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8 = 256 random bits
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy

const port = 3000

const app = express()
app.use(logger('dev'))

const cookieExtractor = req => {
    console.log("Parsing cookie")
    let jwt = null 

    if (req && req.cookies) {
        jwt = req.cookies['jwt']
    }
    console.log(jwt)
    return jwt
}

// Define local strategy
passport.use('local', new LocalStrategy({
        usernameField : 'username',
        passwordField : 'password',
        session: false },
    function (username, password, done){
        if(username === 'walrus' && password === 'walrus'){
            const user = {
                username: 'walrus',
                description: 'the only user that deserves to constact the fortune teller'
            }
            return done(null, user)
        }
        return done(null, false)
    }

))

// Define JWT Strategy
passport.use('jwt', new JwtStrategy({
    jwtFromRequest: cookieExtractor,
    secretOrKey: jwtSecret
    },
    function (jwt_payload, done){
        if(jwt_payload.sub === 'walrus'){
            console.log("User is logged correctly")
            const user = {
                username: 'walrus',
                description: 'description for walrus'
            }
            return done(null, user)
        }
        return done(null, false)
    }
))

// Requirement of passport local strategy
app.use(express.urlencoded({extended: true}))

// Load passport auth middleware
app.use(passport.initialize())

// Load cookie parser 
app.use(cookieParser())

app.get('/', passport.authenticate('jwt', {session: false, failureRedirect: '/login'}),
(req, res) => {
    console.log(req.user.username);
    res.send(fortune.fortune());
})

app.get('/user', (req, res) => {
    const user = {
        name: 'walrus',
        description: 'it is what it is'
    }
    res.json(user)
})

app.get('/login', (req, res) => {
    res.sendFile('login.html', {root: __dirname})
})

app.post('/login', passport.authenticate('local', {failureRedirect: '/login', session: false}), 
    (req, res) => {

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

        // Send the token directly to the browser
        res.cookie('jwt', token, {expires: new Date(Date.now() + 120 * 1000)})
        //res.cookie('jwt', token, {httpOnly: true})
        res.redirect('/')
        
        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }
)

app.get('/logout', (req, res) =>{
    res.clearCookie('jwt')
    res.send("User has been logged out")
})

app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
})

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})
