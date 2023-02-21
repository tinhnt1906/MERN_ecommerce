const jwt = require('jsonwebtoken');

const createAccessToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '15s' });
}

const createRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '80s' });
}

module.exports = { createAccessToken, createRefreshToken }