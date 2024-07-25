const mongoose = require('mongoose');
const Account = mongoose.model('accounts');

const validator = require('validator');
const argon2i = require('argon2-ffi').argon2i;
const crypto = require('crypto');

const passwordRegex = new RegExp('(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,24})');

module.exports = app => {
    // Routes
    app.post('/account/login', async (req, res) => {
        const { username, password } = req.body;

        var response = {};

        if (username == null || !passwordRegex.test(password)) {
            response.status = 0;
            response.msg = "Invalid credentials";
            res.send(response);
            return;
        }

        var userAccount = await Account.findOne({ username: username }, 'username isAdmin password');
        if (userAccount != null) {
            argon2i.verify(userAccount.password, password).then(async success => {
                if (success) {
                    userAccount.lastAuthentication = Date.now();
                    await userAccount.save();

                    response.status = 1;
                    response.msg = "Logged in";
                    response.data = (({username, isAdmin}) => ({username, isAdmin}))(userAccount);
                    res.send(response);
                    return;
                } else {
                    response.status = 0;
                    response.msg = "Invalid credentials";
                    res.send(response);
                    return;
                }
            });
        } else {
            response.status = 0;
            response.msg = "Invalid credentials";
            res.send(response);
            return;
        }
    });

    app.post('/account/register', async (req, res) => {
        const { username, password, email } = req.body;

        var response = {};

        if (username == null || username.length < 5 || username.length > 16) {
            response.status = 0;
            response.msg = "Invalid username";
            res.send(response);
            return;
        }

        if (!validator.isEmail(email)) {
            response.status = 0;
            response.msg = "Invalid email";
            res.send(response);
            return;
        }

        if (!passwordRegex.test(password)) {
            response.status = 0;
            response.msg = "Unsafe password";
            res.send(response);
            return;
        }

        var userAccount = await Account.findOne({ username: username }, '_id');
        if (userAccount == null) {
            console.log("Create new account");

            // Generate a unique hashed password
            crypto.randomBytes(32, function (err, salt) {
                if (err) {
                    console.log(err);
                }

                argon2i.hash(password, salt).then(async hash => {
                    var newAccount = new Account({
                        username: username,
                        password: hash,
                        email: email,
                        salt: salt,

                        lastAuthentication: Date.now(),
                    });

                    await newAccount.save();
                    response.status = 1;
                    response.msg = "Account created";
                    response.data = (({username}) => ({username}))(newAccount);
                    res.send(response);
                    return;
                });
            });
        } else {
            if (userAccount.username == username) {
                response.status = 2;
                response.msg = "Username is already in use";
                res.send(response);
            }
            else if (userAccount.email == email) {
                response.status = 2;
                response.msg = "Email is already in use";
                res.send(response);
            }

            return;
        }
    });
}