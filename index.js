import express, { json, urlencoded } from "express";
import bcrypt from "bcrypt";


/**
 * Relevant and interesting articles:
 *  https://auth0.com/blog/hashing-passwords-one-way-road-to-security/
 *  https://www.youtube.com/watch?v=zt8Cocdy15c
 */

/**
 * Non-persistent user database.
 * Each item contains username and hashed password (with salt).
 * Further improvement: user persistent database, like MongoDB or PostgreSQL. 
*/ 
var user_db = [];

/**
 * Express app.
 */
const app = express();

/**
 * Setup middleware.
 */
app.use(json());
app.use(urlencoded());

/**
 * Routes: 1) GET /login 2) POST /login 3) POST /register
 */

app.get('/login', (req, res) => {
    console.log("login page");
    res.send('<h1>Login Page</h1>');
});

app.post('/login', async (req, res) => {
    const cred = req.body;

    const username = cred.username;
    const password = cred.password;

    const user = user_db.find(item => item.username === username);
    if (user) {
        const match = await bcrypt.compare(password, user.hash);
        
        if (match) {
            res.send({"message":"Successful login."})
        } else {
            res.send({"message":"Failed login. Wrong password."})
        }
    } else {
        res.send({"message":"Failed login. User does not exist."})
    }
});

app.post('/register', verify_registration, async (req, res) => {
    const cred = req.body;

    let username = cred.username;
    let password = cred.password;

    // bcrypt generates hash in the form of $[algorithm]$[cost]$[salt][hash]
    // We dont need to separately store 'salt', 'cost' and 'algorithm'
    // Another algorithm to generate hash: PBKDF2.
    let salt = await bcrypt.genSalt();
    let hash = await bcrypt.hash(password, salt);

    // Add user to database.
    user_db.push({
        username: username,
        hash: hash,
    });
    
    res.send();
});

/**
 * Helper/middleware methods.
 */

function verify_registration(req, res, next) {
    const username = req.body.username;
    const user = user_db.find(item => item.username === username);
    if(user) {
        next({
            statusCode: 400,
            statusMessage: `User ${username} already exists.`
        });
    }
    next();
}

/**
 * Server
 */
const PORT = 5050;
app.listen(PORT, () => {
    console.log(`Listening @ ${PORT}.`);
});