const express = require('express')
const app = express()

const mongoose = require('mongoose')
const cors = require('cors')

mongoose.connect('mongodb://localhost:27017/DIGISIGN_ASSIGNMENT')
.then(() => {
    console.log("Successfully connected to database");  
})
.catch((err) =>{
    console.log(err);
})

//use multiple functions
app.use(express.json())
app.use(cors())
app.use(express.static('uploads'))

//server to show response
app.get('/',(req,res) =>{
    res.send("Hello")
})

const userRouter = require('./routing')
app.use('/', userRouter)
app.listen(8000,() =>{
    console.log("Server Running");
})
