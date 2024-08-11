const express = require('express');
const mysql = require('mysql2');
const app = express();
const cors = require('cors');
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const setRounds = 10;
const jwtSecret = "your_secret_key";

app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    key: "session_username",
    secret: jwtSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        expires: 60 * 10,
    }
}));

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

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = "images";
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
    }
});

app.use('/images', express.static('./images'));

const upload = multer({ storage: storage });

const verifyJWT = (req, res, next) => {
    const token = req.headers["x-access-token"];
    if (!token) {
        return res.status(401).send("Token required for authentication");
    } else {
        jwt.verify(token, jwtSecret, (err, decoded) => {
            if (err) {
                return res.status(403).json({ auth: false, message: "Failed to authenticate" });
            } else {
                req.usermail = decoded.id;
                next();
            }
        });
    }
};

app.get('/isAuth', verifyJWT, (req, res) => {
    res.send("Authenticated Successfully");
});

app.post('/login', (req, res) => {
    const { mail, password } = req.body;

    db.query("SELECT * FROM register WHERE mail=?", [mail], (err, result) => {
        if (err) {
            console.error("Error:", err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (result.length > 0) {
            bcryptjs.compare(password, result[0].password, (err, response) => {
                if (err) {
                    console.error("Error comparing passwords:", err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }
                if (response) {
                    const id = result[0].id;
                    const token = jwt.sign({ id }, jwtSecret, { expiresIn: '1h' });
                    res.json({ auth: true, token, result: result[0], message: 'Login Successful' });
                } else {
                    res.status(401).json({ message: 'Invalid Credentials' });
                }
            });
        } else {
            res.status(401).json({ message: 'Invalid Credentials' });
        }
    });
});

app.post('/register', (req, res) => {
    const { name, mail, contact, address, password, cpassword, category } = req.body;

    if (password !== cpassword) {
        return res.status(400).json({ error: 'Password and Confirm Password do not match' });
    }

    bcryptjs.hash(password, setRounds, (err, hash) => {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        db.query('INSERT INTO register(name, mail, contact, address, category, password) VALUES (?, ?, ?, ?, ?, ?)',
            [name, mail, contact, address, category, hash],
            (err, result) => {
                if (err) {
                    console.error("Database error:", err);
                    return res.status(500).json({ error: 'Internal Server Error' });
                } else {
                    return res.status(200).json({ message: 'Registration Successful' });
                }
            }
        );
    });
});

app.post('/pictures', upload.fields([
    { name: 'front', maxCount: 1 },
    { name: 'back', maxCount: 1 },
    { name: 'rightimage', maxCount: 1 },
    { name: 'leftimage', maxCount: 1 },
    { name: 'speedometer', maxCount: 1 },
    { name: 'lefthandle', maxCount: 1 },
    { name: 'righthandle', maxCount: 1 },
]), (req, res) => {
    const { name, cname, contact, mail, address, area, state, country, geartype, mileage, petrol, price } = req.body;
    const { front, back, rightimage, leftimage, speedometer, lefthandle, righthandle } = req.files;
    const query = `INSERT INTO details (name, cname, contact, mail, address, area, state, country, front, back, rightimage, leftimage, speedometer, lefthandle, righthandle, geartype, mileage, petrol, price)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const values = [
        name, cname, contact, mail, address, area, state, country, front[0].path,back[0].path,rightimage[0].path,leftimage[0].path,speedometer[0].path,lefthandle[0].path,righthandle[0].path, geartype, mileage, petrol, price
    ];

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error', details: err.message });
        } else {
            console.log('Insertion result:', result);
            return res.status(200).json({ message: 'Success' });
        }
    });
});


const PORT = 3003;
app.listen(PORT, () => {
    console.log('Server started on port', PORT);
});
