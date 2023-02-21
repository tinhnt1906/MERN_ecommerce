const router = require('express').Router();
const { verifyUser, register, login, newAccessToken, logout, forgotPassword, resetPassword } = require('../controllers/authController')

router.route('/register')
    .post(register);
router.route('/login')
    .post(login);
router.route('/refresh')
    .post(newAccessToken);
router.route('/logout')
    .post(logout);
router.post('/forgot-password', forgotPassword)
router.put('/reset-password/:token', resetPassword)
router.get('/verify/:id/:token', verifyUser)
module.exports = router;