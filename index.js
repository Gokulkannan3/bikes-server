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

    const db = mysql.createConnection({
        user:'avnadmin',
        password:'AVNS_5W135YZrjuwuLR-WHt5',
        host:'mysql-39af648c-gokul.a.aivencloud.com',
        database:'bikes',
        port:'11941'
    })

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

    const PORT = 3003

    app.listen(PORT,()=>{
        console.log('Server started',PORT);
    });
