const mongoose = require('mongoose');
const { Schema } = mongoose;

const gameAccessSchema = new Schema({
    userId: String,
    lastVisit: Date,
});

mongoose.model('game-access', gameAccessSchema);