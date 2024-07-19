const express = require('express');
const keys = require('./config/keys.js');
const app = express();

// Setting up db
const mongoose = require('mongoose');
mongoose.connect(keys.mongoURI);

// Setup db models
require('./model/Account');

// Setup the routes
require('./routes/authenticationRoutes')(app);

app.listen(keys.port, () => {
    console.log("Listening on " + keys.port);
})