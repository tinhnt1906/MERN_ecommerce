const User = require('../models/user');
const asyncHandler = require('express-async-handler');
const ErrorHandler = require('../utils/errorHandler');

const index = asyncHandler(async (req, res, next) => {
    const users = User.findById(req.user.id);
    console.log(users);
    return res.status(200).json({
        success: users ? true : false,
        message: users ? 'get users successfully' : 'Something went wrong'
    })
})

module.exports = { index }