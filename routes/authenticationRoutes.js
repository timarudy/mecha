const mongoose = require('mongoose');
const Account = mongoose.model('accounts');

const validator = require('validator');
const argon2i = require('argon2-ffi').argon2i;
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const UserOTPVerification = require("../model/userOTPVerification");
const nodemailer = require('nodemailer');
const keys = require('../config/keys');

const passwordRegex = new RegExp('(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,24})');

let transporter = nodemailer.createTransport({
    host: "smtp.ukr.net",
    port: 465,
    secure: true,
    auth: {
        user: keys.email,
        pass: keys.pass,
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.log(error.message);
    }
});

// Required modules and initial setup omitted for brevity

module.exports = app => {
    app.post('/account/data', async (req, res) => {
        const { username } = req.body;

        try {
            const account = await Account.findOne({ username });
            const exists = account != null;
            res.json({
                exists,
            });
        } catch (err) {
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    app.post('/account/login', async (req, res) => {
        try {
            const { username, password } = req.body;
            let response = {};

            if (!username || !passwordRegex.test(password)) {
                response.status = 0;
                response.msg = "Invalid credentials";
                return res.json(response);
            }

            let userAccount = await Account.findOne({ username }, 'username isAdmin password email confirmed');
            if (userAccount) {
                const success = await argon2i.verify(userAccount.password, password);
                if (success) {
                    userAccount.lastAuthentication = Date.now();
                    await userAccount.save();

                    response.status = 1;
                    response.msg = "Logged in";
                    const { _id } = userAccount;
                    response.data = {
                        username,
                        isAdmin: userAccount.isAdmin,
                        email: userAccount.email,
                        confirmed: userAccount.confirmed,
                        _id: _id,
                    };
                    return res.json(response);
                }
            }

            response.status = 0;
            response.msg = "Invalid credentials";
            res.json(response);
        } catch (error) {
            res.status(500).json({ status: 0, msg: 'Internal server error' });
            console.error(error);
        }
    });

    app.post('/account/register', async (req, res) => {
        try {
            const { username, password, email } = req.body;
            let response = {};

            if (!username || username.length < 5 || username.length > 16) {
                response.status = 0;
                response.msg = "Invalid username";
                return res.json(response);
            }

            if (!validator.isEmail(email)) {
                response.status = 0;
                response.msg = "Invalid email";
                return res.json(response);
            }

            if (!passwordRegex.test(password)) {
                response.status = 0;
                response.msg = "Unsafe password";
                return res.json(response);
            }

            let userAccount = await Account.findOne({ username }, '_id email');
            let userAccount2 = await Account.findOne({ email });
            if (!userAccount && !userAccount2) {
                crypto.randomBytes(32, async (err, salt) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({
                            status: 0,
                            msg: 'Internal server error'
                        });
                    }

                    try {
                        const hash = await argon2i.hash(password, salt);
                        const newAccount = new Account({
                            username,
                            password: hash,
                            email,
                            salt,
                            isAdmin: false,
                            confirmed: false,
                            lastAuthentication: Date.now(),
                        });

                        await newAccount.save();
                        // await sendOTPVerificationEmail(newAccount, res);

                        response.status = 1;
                        response.msg = "Account created";
                        const { _id } = newAccount;
                        response.data = {
                            _id,
                            email,
                            username,
                        };

                        res.json(response);
                    } catch (error) {
                        console.error(error);
                        res.status(500).json({
                            status: 0,
                            msg: 'Internal server error'
                        });
                    }
                });
            } else {
                if (userAccount != null) {
                    response.msg = "Username is already in use";
                } else {
                    response.msg = "Email is already in use"
                }
                response.status = 2;
                res.json(response);
            }
        } catch (error) {
            res.status(500).json({ status: 0, msg: 'Internal server error' });
            console.error(error);
        }
    });

    app.post('/account/confirmation', async (req, res) => {
        try {
            let { userId, otp } = req.body;

            if (!userId || !otp) {
                throw new Error("Empty otp is not allowed");
            } else {
                const UserOTPVerificationRecords = await UserOTPVerification.find({
                    userId,
                });
                if (UserOTPVerificationRecords.length <= 0) {
                    throw new Error("Account record does not exist or it has been already confirmed");
                } else {
                    const { expiresAt } = UserOTPVerificationRecords[0];
                    const hashedOTP = UserOTPVerificationRecords[0].otp;

                    if (expiresAt < Date.now()) {
                        await UserOTPVerification.deleteMany({ userId });
                        throw new Error("Code has expired. Please request again.");
                    } else {
                        const validOTP = await bcrypt.compare(otp, hashedOTP);

                        if (!validOTP) {
                            throw new Error("Invalid code passed");
                        } else {
                            await Account.updateOne({ _id: userId }, { confirmed: true });
                            await UserOTPVerification.deleteMany({ userId });
                            res.json({
                                status: 1,
                                msg: "Email confirmed",
                            });
                        }
                    }
                }
            }
        } catch (error) {
            res.json({
                status: 0,
                msg: error.message,
            });
        }
    });

    app.post('/account/request-otp', async (req, res) => {
        try {
            const { userId } = req.body;

            if (!userId) {
                console.log("User ID is required");
                return res.status(400).json({
                    status: 0,
                    msg: 'User ID is required'
                });
            }

            // Check if the user exists and is not confirmed
            const userAccount = await Account.findById(userId);
            if (!userAccount) {
                return res.status(404).json({
                    status: 0,
                    msg: 'User not found'
                });
            }

            if (userAccount.confirmed) {
                return res.status(400).json({
                    status: 0,
                    msg: 'Email is already confirmed'
                });
            }

            // Use the existing function to send a new OTP
            await sendOTPVerificationEmail(userAccount, res);
        } catch (error) {
            console.error('Failed to request OTP:', error);
            res.status(500).json({
                status: 0,
                msg: 'Internal server error'
            });
        }
    });
};

const sendOTPVerificationEmail = async ({ _id, email, username }, res) => {
    try {
        const otp = `${Math.floor(Math.random() * 9000 + 1000)}`;

        const mailOptions = {
            from: keys.email,
            to: email,
            subject: "Verify Your Email",
            html: `<p>Hey, ${username} enter <b>${otp}</b> in <b>mecha</b> to verify your email</p>`,
        };

        const hashedOTP = await bcrypt.hash(otp, 10);

        const verification = await UserOTPVerification.findOne({ userId: _id });

        let response = {};

        if (verification) {
            if (verification.expiresAt < Date.now()) {
                await UserOTPVerification.deleteOne({ userId: _id });

                const newOTPVerification = new UserOTPVerification({
                    userId: _id,
                    otp: hashedOTP,
                    createdAt: Date.now(),
                    expiresAt: Date.now() + 120000,
                });

                await newOTPVerification.save();
                await transporter.sendMail(mailOptions);

                response.status = 1;
                response.msg = "Verification sent";
                response.data = {
                    _id,
                    email,
                    username,
                };
            } else {
                response.status = 1;
                response.msg = "Use previous verification code";
                response.data = {
                    _id,
                    email,
                    username,
                };
            }
        } else {
            const newOTPVerification = new UserOTPVerification({
                userId: _id,
                otp: hashedOTP,
                createdAt: Date.now(),
                expiresAt: Date.now() + 120000,
            });

            await newOTPVerification.save();
            await transporter.sendMail(mailOptions);

            response.status = 1;
            response.msg = "Verification sent";
            response.data = {
                _id,
                email,
                username,
            };
        }

        res.json(response);
    } catch (error) {
        console.error('Failed to send verification email:', error);
        res.status(500).json({ status: "FAIL", message: 'Failed to send verification email' });
    }
};
