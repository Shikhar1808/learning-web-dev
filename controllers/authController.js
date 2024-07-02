const User = require('../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const jwt = require("jsonwebtoken");
const AppError = require("../utils/appError");

const secretKey = process.env.JWT_SECRET;

const signToken = id =>{
    return jwt.sign({id},secretKey,{ expiresIn: process.env.JWT_EXPIRES_IN})
}

exports.signup = catchAsync(async (req, res) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm
    });

    const token = signToken(newUser._id)

    res.status(201).json({
        status: 'success',
        token,
        data: {
            user: newUser
        }
    })
} )

exports.login = catchAsync(async(req,res,next)=>{
    const {email,password} = req.body;

    //1) Check if email and pass exists
    if(!email || !password){
        return next(new AppError('Please provide a valid email and password',400))
    }

    //2) Check if user exists and password is correct
    const user = await User.findOne({email}).select('+password');
    //we selected the password here because we removed we set it to falls in userSchema
    // console.log(user)
    if(!user || !await user.correctPassword(password, user.password)){
        return next(new AppError("Incorrect Email or Password",401))
    }

    //#) Sent the token to the client
    token = signToken(user._id),
    res.status(200).json({
        staus:"success",
        token
    })
})

exports.protect = catchAsync(async(req,res, next)=>{
    //1) Getting token and check it it exists
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1]
    }
    // console.log(token);

    if(!token){
        return next(new AppError("Your are not logged in",401))
    }

    //2) validate the token(Verification)


    //3) Check if user still exists


    //4) Check if the user changed the password after the JWT was issued

    
    next();
})