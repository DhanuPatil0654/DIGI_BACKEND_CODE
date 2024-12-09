const mongoose = require('mongoose')

const userdata = mongoose.Schema({
    signerid : String,
    pdfFile : String,
    txn: { type: String, required: false },
    ts: { type: String, required: false },
})

module.exports =  mongoose.model('digi_sign_assignment',userdata)