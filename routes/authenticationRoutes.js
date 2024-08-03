const mongoose = require('mongoose');
const Account = mongoose.model('accounts');
const Appointment = mongoose.model('appointments');

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

            let appointments = {};

            if (exists) {
                const { _id } = account;
                appointments = await Appointment.find({ userId: _id });
            }

            res.json({
                exists,
                appointments,
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

    app.post('/account/send-appointment-form', async (req, res) => {
        try {
            const { userId, userName, problem, date, time, email } = req.body;

            const chosenDate = new Date(date);
            const userAccount = await Account.findById(userId);

            if (!userId) {
                console.log("User ID is required");
                return res.status(400).json({
                    status: 0,
                    msg: 'User ID is required'
                });
            }

            const appointments = await Appointment.find({ userId });

            if (appointments.length > 3) {
                console.log("More than 3 appointments at a time are prohibited");
                return res.status(400).json({
                    status: 0,
                    msg: 'Maximum 3 appointments'
                });
            }

            const appointment = await Appointment.findOne({ date, time });

            if (appointment) {
                console.log("This date or time is already taken");
                return res.status(400).json({
                    status: 0,
                    msg: 'Taken date or time'
                });
            }

            if (chosenDate.getTime() <= Date.now()) {
                console.log("The date cannot be earlier than today");
                return res.status(400).json({
                    status: 0,
                    msg: 'Incorrect date'
                });
            }

            if (chosenDate.getTime() > Date.now() + 15552000000) {
                console.log("You can make an appointment at least 3 month before the actual appointment");
                return res.status(400).json({
                    status: 0,
                    msg: 'Incorrect date'
                });
            }

            if (!userAccount.confirmed) {
                console.log("Not confirmed email");
                return res.status(400).json({
                    status: 0,
                    msg: 'Confirm email first'
                });
            }

            const newAppointment = new Appointment({
                userId,
                date,
                time,
            });

            await newAppointment.save();

            const adminMailOptions = {
                from: keys.email,
                to: "tymurrudenko2005@gmail.com",
                subject: `Appointment of ${userName}`,
                html: `
                <html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            color: #333;
                            padding: 20px;
                        }
                        .container {
                            background-color: #fff;
                            padding: 20px;
                            border-radius: 10px;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        }
                        .header {
                            font-size: 24px;
                            font-weight: bold;
                            margin-bottom: 20px;
                            color: #0056b3;
                        }
                        .details {
                            font-size: 16px;
                            line-height: 1.6;
                        }
                        .details p {
                            margin: 5px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">New Appointment Request</div>
                        <div class="details">
                            <p><strong>Name:</strong> ${userName}</p>
                            <p><strong>Date:</strong> ${date}</p>
                            <p><strong>Time:</strong> ${time}</p>
                            <p><strong>Problem explained:</strong> ${problem}</p>
                        </div>
                    </div>
                </body>
                </html>
                `,
            };

            const customerMailOptions = {
                from: keys.email,
                to: email,
                subject: `Appointment to mecha`,
                html: `
                <html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            color: #333;
                            padding: 20px;
                        }
                        .container {
                            background-color: #fff;
                            padding: 20px;
                            border-radius: 10px;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        }
                        .header {
                            font-size: 24px;
                            font-weight: bold;
                            margin-bottom: 20px;
                            color: #28a745;
                        }
                        .message {
                            font-size: 16px;
                            line-height: 1.6;
                        }
                        .message p {
                            margin: 10px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">Appointment Confirmation</div>
                        <div class="message">
                            <p>Hey, <strong>${userName}</strong>!</p>
                            <p>You successfully made an appointment to us on <strong>${date}</strong> at <strong>${time}</strong>.</p>
                            <p>See you soon!</p>
                        </div>
                    </div>
                </body>
                </html>
                `,
            }

            await transporter.sendMail(adminMailOptions);
            await transporter.sendMail(customerMailOptions);

            let response = {};

            response.status = 1;
            response.msg = "Verification sent";

            res.json(response);
        } catch (error) {
            console.error('Failed to request OTP:', error);
            res.status(500).json({
                status: 0,
                msg: 'Internal server error'
            });
        }
    });

    app.post('/account/delete-appointment', async (req, res) => {
        try {
            const { date, time } = req.body;

            const appointment = await Appointment.findOne({ date, time });
            let response = {};

            if (!appointment) {
                response.status = 0;
                response.msg = "Appointment does not exist";
                return res.json(response);
            }

            await Appointment.deleteOne(appointment);

            response.status = 1;
            response.message = "Deleted";
            return res.json(response);
        } catch (error) {
            res.status(500).json({ status: 0, msg: 'Internal server error' });
            console.error(error);
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
            html: `
            <html>
            <head>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        color: #333;
                        padding: 20px;
                    }
                    .container {
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 10px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }
                    .header {
                        font-size: 24px;
                        font-weight: bold;
                        margin-bottom: 20px;
                        color: #ffcc00;
                    }
                    .message {
                        font-size: 16px;
                        line-height: 1.6;
                    }
                    .message p {
                        margin: 10px 0;
                    }
                    .otp {
                        font-size: 20px;
                        font-weight: bold;
                        color: #ff0000;
                        text-align: center;
                        margin: 20px 0;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">Email Verification</div>
                    <div class="message">
                        <p>Hey, <strong>${username}</strong>!</p>
                        <p>Enter the following OTP code in <strong>mecha</strong> to verify your email:</p>
                        <div class="otp">${otp}</div>
                        <p>This code is valid for 2 minutes.</p>
                    </div>
                </div>
            </body>
            </html>
            `,
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
