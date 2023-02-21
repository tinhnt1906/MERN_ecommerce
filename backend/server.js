const express = require('express');
require('dotenv').config();
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const dbConnect = require('./configs/dbConnect');
const initRoutes = require('./routes')
const errorHandler = require("./middlewares/errorHandler");

const app = express();
const PORT = process.env.PORT;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.json());



dbConnect();
initRoutes(app);
app.use(errorHandler)
app.listen(PORT, () => {
    console.log('Server running on the PORT: ' + PORT);
})