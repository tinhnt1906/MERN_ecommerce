const User = require('../models/user');
const Token = require('../models/token');
const asyncHandler = require('express-async-handler');
const { registerValidate, loginValidate } = require('../validation/authValidate')
const ErrorHandler = require('../utils/errorHandler');
const { createAccessToken, createRefreshToken } = require('../middlewares/jwt');
const jwt = require('jsonwebtoken')
const { sendMail } = require('../utils/sendEmail')
const crypto = require('crypto');

const register = asyncHandler(async (req, res, next) => {

    const { error } = registerValidate(req.body);
    if (error) {
        return next(new ErrorHandler(error.details[0].message));
    }

    const { email, password, firstName, lastName, mobile } = req.body;
    const user = await User.findOne({ email })
    if (user)
        return next(new ErrorHandler('This email is already used.', 409));

    const newUser = await User.create({ email, password, lastName, firstName, mobile });

    //tạo token dùng để xác minh id
    const token = await Token.create({
        userId: newUser._id,
        token: crypto.randomBytes(32).toString("hex"),
    });

    const message = `http://localhost:9000/api/v1/auth/verify/${newUser._id}/${token.token}`;
    const data = {
        to: newUser.email,
        text: `Hey ${newUser.firstName + ' ' + newUser.lastName}`,
        subject: "Verify Email",
        html: message,
    };
    sendMail(data);

    return res.status(200).json({
        success: newUser ? true : false,
        message: newUser ? 'Register successfully. An Email sent to your account please verify' : 'Something went wrong'
    })
})


const verifyUser = asyncHandler(async (req, res, next) => {
    const { id } = req.params;
    const user = await User.findById(id);
    console.log(user._id);
    if (!user)
        return next(new ErrorHandler('user not found', 404));

    const token = await Token.findOne({
        userId: user._id,
        token: req.params.token,
    })

    if (!token)
        return next(new ErrorHandler('Invalid link', 400));

    await User.findByIdAndUpdate(id, { isVerified: true }, { new: true });
    await Token.findByIdAndRemove(token._id);
    return res.status(200).json({
        success: token ? true : false,
        message: token ? 'email verified sucessfully' : 'Something went wrong'
    })
})

const login = asyncHandler(async (req, res, next) => {
    //validate
    const { error } = loginValidate(req.body);
    if (error) {
        return next(new ErrorHandler(error.details[0].message));
    }

    const { email, password } = req.body;

    //check user
    const user = await User.findOne({ email }).select('-refreshToken');
    if (!user)
        return next(new ErrorHandler('email not found', 404));

    //check password
    const isPasswordMatch = await user.comparePassword(password);
    if (!isPasswordMatch)
        return next(new ErrorHandler('password invalid', 404));

    if (!user.isVerified)
        return next(new ErrorHandler('Your account is not verified, please verify', 404));

    if (user && isPasswordMatch) {
        //get userData -password and role
        const { password, role, ...userData } = user.toObject();

        //create access token
        const accessToken = createAccessToken(user._id);

        //create refresh token
        const refreshToken = createRefreshToken(user._id);

        //save refresh token to database
        await User.findByIdAndUpdate(user._id, { refreshToken }, { new: true });

        //save refresh token to cookie
        res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 })
        return res.status(200).json({
            success: true,
            accessToken,
            userData
        })
    }
})

const newAccessToken = asyncHandler(async (req, res, next) => {
    // lay refresh token từ cookie
    const cookie = req.cookies;
    const refreshToken = cookie?.refreshToken;

    //check refresh token có tồn tại không
    if (!refreshToken)
        return next(new ErrorHandler('No Refresh Token in Cookies', 404));

    // kiểm tra token có hợp lệ trong db không => trả về user
    const user = User.findOne({ refreshToken });
    if (!user)
        return next(new ErrorHandler('No Refresh token present. please login again', 404));

    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decode) => {
        if (err)
            return next(new ErrorHandler('There is something wrong with refresh token'))

        const accessToken = createAccessToken(user?._id);
        return res.status(200).json({
            success: true,
            accessToken,
        })
    })
})

const logout = asyncHandler(async (req, res, next) => {
    // lay refresh token từ cookie
    const cookie = req.cookies;
    const refreshToken = cookie?.refreshToken;
    if (!refreshToken)
        return next(new ErrorHandler('No Refresh Token in Cookies', 404));
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true
    })
    return res.status(200).json({
        success: true,
        message: 'Logout successfully'
    })
});

const forgotPassword = asyncHandler(async (req, res, next) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user)
        return next(new ErrorHandler('User not found with this email', 404));
    try {
        const token = await user.createPasswordResetToken();
        await user.save();
        const resetURL = `Hi, Please follow this link to reset Your Password. 
        This link is valid till 10 minutes from now. <a href='http://localhost:9000/api/v1/auth/reset-password/${token}'>Click Here</>`;
        const data = {
            to: email,
            text: `Hey ${user.firstName + ' ' + user.lastName}`,
            subject: "Forgot Password Link",
            html: resetURL,
        };

        sendMail(data);

        res.json(
            token
        );
    } catch (error) {
        console.log(error);
    }
});

const resetPassword = asyncHandler(async (req, res, next) => {
    const { password } = req.body;
    const { token } = req.params;
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
    });
    if (!user)
        return next(new ErrorHandler('Token Expired, Please try again later', 404));

    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
    res.json(user);
});

module.exports = { register, login, newAccessToken, logout, forgotPassword, resetPassword, verifyUser }