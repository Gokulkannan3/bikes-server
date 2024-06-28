const express = require('express');
const mysql = require('mysql2');
const app = express();
const cors =require('cors');
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("cookie-parser");
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const setRounds=10;
const fs = require('fs');

app.use(express.json());
app.use(cors({origin:'*'}));
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended:true}));

app.use(
    session({
        key: "username",
        secret: "success",
        resave: false,
        saveUninitialized: false,
        cookie:{
            expires: 60 * 10,
        }
    })
)

var db = mysql.createConnection({
    host: "gokul-server.mysql.database.azure.com",
    user: "Gokul",
    password: "G0kul@3112003",
    database: "gokul",
    port: 3306,
    ssl: {
        ca: fs.readFileSync("./DigiCertGlobalRootG2.crt.pem"),
        rejectUnauthorized: false
    }
});


const connectToDatabase = () => {
    db.connect((err) => {
        if (err) {
            console.error('Error connecting to database:', err);
            console.log('Retrying connection in 5 seconds...');
            setTimeout(connectToDatabase, 5000);
        } else {
            console.log("Connected to database");
        }
    });
};

connectToDatabase();

    const verifyJWT = (req, res, next) => {
        const token = req.headers["x-access-token"];
        if (!token) {
            res.send("We need token give it next time");
        } else {
            jwt.verify(token, "secret", (err, decoded) => {
                if (err) {
                    res.json({ auth: false, message: "Failed to authenticate" });
                } else {
                    req.usermail = decoded.id;
                    next();
                }
            });
        }
    };
    
    
    app.get('/isAuth',verifyJWT,(req,res)=>{
        res.send("Authenticeted Successfully");
    })
    
    app.post('/login', async (req, res) => {
        const mail = req.body?.mail;
        const password = req.body?.password;
    
        db.query(
            "SELECT * FROM register WHERE mail=?",
            [mail],
            (err, result) => {
                if (err) {
                    console.log("Error:", err);
                    res.status(500).json({ error: 'Internal Server Error' });
                    return;
                }
    
                if (result.length > 0) {
                    bcryptjs.compare(password, result[0].password, (err, response) => {
                        if (response) {
                            const id  = result[0].id;
                            const token = jwt.sign({ id }, "success", { expiresIn: 5 });
                            res.json({ auth: true, token: token, result: result[0], message: 'Login Successful' });
                        } else {
                            res.status(401).json({ message: 'Invalid Credentials' });
                        }
                    });
                } else {
                    res.status(401).json({ message: 'Invalid Credentials' });
                }
            }
        );
    });
    
    const verJWT = (req, res, next) => {
        const token = req.headers["x-access-token"];
        if (!token) {
            res.send("We need token give it next time");
        } else {
            jwt.verify(token, "secret", (err, decoded) => {
                if (err) {
                    res.json({ auth: false, message: "Failed to authenticate" });
                } else {
                    req.usermail = decoded.id;
                    next();
                }
            });
        }
    };
    
    app.get('/isAauth', verJWT, (req, res) => {
        const userDetails = {
            usermail: req.usermail,
        };
    
        res.json({ result: [userDetails] });
    });

    app.post('/register', (req, res) => {
        const name = req.body?.name;
        const mail = req.body?.mail;
        const contact = req.body?.contact;
        const address = req.body?.address;
        const password = req.body?.password;
        const cpassword = req.body?.cpassword;
        const category = req.body?.category;

        console.log(req.body);

        if (password !== cpassword) {
            return res.status(400).json({ error: 'Password and Confirm Password do not match' });
        }

        bcryptjs.hash(password,setRounds,(err,hash)=>{
            if(err){
                console.log(err)
            }

            db.query('INSERT INTO register(name, mail, contact, address, category, password, cpassword) VALUES (?,?,?,?,?,?,?)',
            [name, mail, contact, address,category, hash, hash],
            (err, result) => {
                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                } else {
                    console.log(result);
                    return res.status(200).json({ message: 'Registration Successful' });
                }
            }
        );
        })
    });

    app.post('/cregister', (req, res) => {
        const name = req.body?.name;
        const mail = req.body?.mail;
        const cname = req.body?.cname;
        const contact = req.body?.contact;
        const address = req.body?.address;
        const area  = req.body?.area;
        const state = req.body?.state;
        const country = req.body?.country;
        const password = req.body?.password;
        const cpassword = req.body?.cpassword;
        const category = req.body?.category;

        console.log(req.body);

        if (password !== cpassword) {
            return res.status(400).json({ error: 'Password and Confirm Password do not match' });
        }

        bcryptjs.hash(password,setRounds,(err,hash)=>{
            if(err){
                console.log(err)
            }

            db.query('INSERT INTO cregister(name, mail, cname, contact, address, area, state, country, category, password, cpassword) VALUES (?,?,?,?,?,?,?)',
            [name, mail, cname, contact, address, area, state, country, category, hash, hash],
            (err, result) => {
                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                } else {
                    console.log(result);
                    return res.status(200).json({ message: 'Registration Successful' });
                }
            }
        );
        })
    });

    const PORT = 3003

    app.listen(PORT,()=>{
        console.log('Server started',PORT);
    });
