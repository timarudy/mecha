const mongoose = require('mongoose');
const Account = mongoose.model('accounts');

module.exports = app => {
    // Routes
    app.get('/account', async (req, res) => {
        const { username, password } = req.query;

        if (username == null || password == null) {
            res.send("Invalid credentials");
            return;
        }

        var userAccount = await Account.findOne({ username: username });
        if (userAccount == null) {
            console.log("Try create new account");

            var newAccount = new Account({
                username: username,
                password: password,

                lastAuthentication: Date.now(),
            });

            await newAccount.save();

            res.send(newAccount);

            return;
        } else {
            if (password == userAccount.password) {
                userAccount.lastAuthentication = Date.now();
                await userAccount.save();

                res.send(userAccount);
            }
        }

        // res.send('Invalid credentials...');
        return;
    })
}