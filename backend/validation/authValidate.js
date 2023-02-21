const Joi = require('joi')

const registerValidate = data => {
    const userSchema = Joi.object({
        email: Joi.string()
            .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
            .required(),
        password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{6,30}$'))
            .required(),
        firstName: Joi.string().required(),
        lastName: Joi.string().required(),
        mobile: Joi.string().required(),
    })
    return userSchema.validate(data);
}

const loginValidate = data => {
    const userSchema = Joi.object({
        email: Joi.string()
            .required(),
        password: Joi.string().required(),
    })
    return userSchema.validate(data);
}


module.exports = {
    registerValidate,
    loginValidate
}