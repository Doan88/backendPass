const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const port = process.env.PORT;
const app = express();
const dbPasswords = new sqlite3.Database('passwords.db');
const dbUsers = new sqlite3.Database('users.db');
const secretKey = '7ba0fc69ca743de9e0656a02a11ca76efd628c5fb9565c24776c9cf6e5b137d082891af8491aa1621cd821cf04e070b4621038c28d2c3fef3c03b0b7cc2e064d';

app.use(express.json());
app.use(cors());

dbUsers.run(`CREATE TABLE IF NOT EXISTS users 
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

dbPasswords.run(`CREATE TABLE IF NOT EXISTS passwords
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account TEXT,
        password TEXT,
        notes TEXT,
        userId INTEGER,
        FOREIGN KEY(userId) REFERENCES users(id)
    )`);

// Middleware to protect routes
function authMiddleware(req,res,next){
    const token =  req.headers.authorization?.split(' ')[1];
    if(!token)
        return res.status(401).json({ error: 'Invalid token' });
    try{
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded;
        next();
    }
    catch(err){
        res.status(403).json({ error: err.message });
    }
};

// Register
app.post('/register',(req,res) => {
    const {username,password} = req.body;
    const hashed = bcrypt.hashSync(password,8);
    dbUsers.run(`INSERT INTO users(username,password) VALUES(?,?)`,[username,hashed],function(err){
        if(err)
            return res.status(400).json({error:'Username taken'});
        res.json({status:'USER REGISTERED SUCCESSFULLY'});
    })
});

// Login
app.post('/login',(req,res) => {
    const {username,password} = req.body;
    dbUsers.get(`SELECT * FROM users WHERE username = ?`,[username],(err,user) => {
        if (err || !user){
            return res.status(400).json({error:'Invalid username'});
        }
        if(!bcrypt.compareSync(password,user.password)){
            return res.status(401).json({error:'Wrong password'});
        }
        const token = jwt.sign({userId: user.id}, secretKey, {expiresIn:'1h'});
        res.json({ token, userId: user.id });
    });
});

// GET: Retrieve all the passwords
app.get('/showall',authMiddleware ,(req,res) =>{
    dbPasswords.all('SELECT * FROM passwords WHERE userId = ?', [req.user.userId], function(err,rows) {
        if (err){
            console.log('Cannot get the passwords');
            return res.json({error:err.message});
        }
        console.log('Get all the password successfully');
        res.json(rows);
    });
});

// POST: Add new password
app.post('/addnew',authMiddleware , (req,res)=>{
    const {account,password,notes} = req.body;
    if(account === '' || password === ''){
        console.error('Account and password must not be empty');
        return;
    }
    dbPasswords.run('INSERT INTO passwords (account,password,notes,userId) values (?,?,?,?)',[account,password,notes,req.user.userId], function(err) {
        if(err){
            console.log('Cannot add new password');
            return res.json({error:err.message});
        }
        console.log('Add new password successfully');
        res.json({status:'ADD NEW PASSWORD SUCCESSFULLY'}); 
    });
});


// DELETE: Delete all passwords
app.delete('/deleteall',authMiddleware , (req,res) =>{
    dbPasswords.run('DELETE FROM passwords WHERE userId = ?',[req.user.userId],function(err){
        if(err){
            console.log('Cannot delete all passwords');
            return res.json({error:err.message});
        }
        console.log('Delete all passwords successfully');
        res.json({status:'DELETE ALL PASSWORDS SUCCESSFULLY'});
    });
});

// PUT: Edit password by id
app.put('/edit/:id',authMiddleware , (req,res)=>{
    const {account,password,notes} = req.body;
    const {id} = req.params;
    dbPasswords.run('UPDATE passwords SET account = ?, password = ?, notes = ? WHERE id = ? AND userId = ?',[account,password,notes,id,req.user.userId], function(err){
        if(err){
            console.log('Cannot update the password');
            return res.json({error:err.message});
        }
        console.log('Update password successfully');
        res.json({status:'UPDATE PASSWORD SUCCESSFULLY'});
    });
});

// DELETE: Delete password by id
app.delete('/delete/:id',authMiddleware ,(req,res)=>{
    const {id} = req.params;
    dbPasswords.run('DELETE FROM passwords WHERE id = ? AND userId = ?',[id,req.user.userId],function(err){
        if(err){
            console.log('Cannot delete the password');
            return res.json({error:err.message});
        }
        console.log('Delete password successfully');
        res.json({status:'DELETE PASSWORD SUCCESSFULLY'});
    });
});

app.listen(port,()=>{
    console.log(`Backend server running on ${port}`);
}
);


