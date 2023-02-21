const router = require('express').Router();
const { index } = require('../controllers/userController')
const { isAuthenticated } = require('../middlewares/verifyToken');

router.route('/')
    .get(isAuthenticated, index);

module.exports = router;