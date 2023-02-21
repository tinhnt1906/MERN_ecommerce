const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler');
const ErrorHandler = require('../utils/errorHandler');

const isAuthenticated = asyncHandler(async (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization
    if (!authHeader?.startsWith('Bearer'))
        return next(new ErrorHandler("no token provided, access denied", 401));

    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decode) => {
        if (err)
            return next(new ErrorHandler('invalid token, access denied', 401));
        console.log(decode);
        req.user = decode;
        next();
    })
});

module.exports = { isAuthenticated }