const mongoose = require('mongoose');
const Account = mongoose.model('accounts');

const argon2i = require('argon2-ffi').argon2i;
const crypto = require('crypto');

module.exports = app => {
    // Routes
    app.post('/account/login', async (req, res) => {
        const { username, password } = req.body;

        if (username == null || password == null) {
            res.send("Invalid credentials");
            return;
        }

        var userAccount = await Account.findOne({ username: username });
        if (userAccount != null) {
            // if (password == userAccount.password) {
            //     userAccount.lastAuthentication = Date.now();
            //     await userAccount.save();

            //     res.send(userAccount);
            //     return;
            // }
            argon2i.verify(userAccount.password, password).then(async success => {
                if (success) {
                    userAccount.lastAuthentication = Date.now();
                    await userAccount.save();
                    res.send(userAccount);
                    return;
                } else {

                    res.send('Invalid credentials...');
                    return;
                }
            });
        }

    })

    app.post('/account/register', async (req, res) => {
        const { username, password, email } = req.body;

        if (username == null || password == null || email == null) {
            res.send("Invalid credentials");
            return;
        }

        var userAccount = await Account.findOne({ username: username });
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
                    res.send(newAccount);
                    return;
                });
            });
        } else {
            if (userAccount.username == username) {
                res.send('This username is already taken...');
            }
            else if (userAccount.email == email) {
                res.send('This email is already taken...');
            }

            return;
        }
    })
}