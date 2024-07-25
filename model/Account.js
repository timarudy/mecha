const mongoose = require('mongoose');
const { Schema } = mongoose;

const accountSchema = new Schema({
    username: String,
    password: String,
    email: String,
    salt: String,
    confirmed: Boolean,
    isAdmin: Boolean,
    
    lastAuthentication: Date,
});

mongoose.model('accounts', accountSchema);