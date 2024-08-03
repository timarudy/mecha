const mongoose = require('mongoose');
const { Schema } = mongoose;

const appointmentSchema = new Schema({
    userId: String,
    userName: String,
    problem: String,
    date: String,
    time: String,
    isAccepted: Boolean,
});

mongoose.model('appointments', appointmentSchema);