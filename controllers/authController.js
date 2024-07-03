const User = require('../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const jwt = require("jsonwebtoken");
const AppError = require("./../utils/appError");
const {promisify} = require('util')
const sendEmail = require("./../utils/email")
const crypto = require('crypto')

const secretKey = process.env.JWT_SECRET;

const signToken = id =>{
    return jwt.sign({id},secretKey,{ expiresIn: process.env.JWT_EXPIRES_IN})
}

exports.signup = catchAsync(async (req, res) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.passwordConfirm,
        passwordChangedAt: req.body.passwordChangedAt,
        role: req.body.role
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
    const decoded = await promisify(jwt.verify)(token, secretKey,)
    // console.log(decoded);

    //3) Check if user still exists
    const freshUser = await User.findById(decoded.id);
    if(!freshUser){
        return next(new AppError('The token belonging to the user doesnt exists',401))
    }

    //4) Check if the user changed the password after the JWT was issued
    if(freshUser.changedPasswordAfter(decoded.iat)){
        return next(new AppError('User recently changed password! Please login again',401))
    }
    //what is iat? iat is the time when the token was issued
    //what we did here is that we are checking if the user changed the password after the token was issued
    
    //Grant access to protected route
    req.user = freshUser;
    //here req.user is the user who is logged in
    next();
})

exports.restrictTo = (...roles)=>{
    return (req,res,next) =>{
        //roles are in an array
        if(!roles.includes(req.user.role)){
            return next(new AppError("You do not have permission to perform this action",403))
        }
        next();
    }

    //with this middleware we can restrict the user to perform some actions
    //we can pass the roles as an argument to this middleware
    //then we can check if the user role is in the roles array
    //we can user req.user because we have the user in the request object from the protect middleware as it will be executed before this middleware
}

exports.forgotPassword = catchAsync(async(req,res,next)=>{
    //1) Get user based on POSTed email
    const user = await User.findOne({email: req.body.email});
    if(!user){
        return next(new AppError('There is no user with email address',404));
    }

    //2) Generate the random token
    const resetToken = user.correctPasswordResetToken();
    await user.save({validateBeforeSave: false});
    //we are saving the user with the validateBeforeSave set to false because we are not validating the passwordConfirm field


    //3) Send it back as an email
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password submit your patch request with your new passwordConfirm to: ${resetURL}. \nIf yoy didnt forgot this password, please ignore your email `

    try{
        await sendEmail({
            email: user.email,
            subject: "Your password reset token",
            message
        })
    
        res.status(200).json({
            status: "success",
            message: "Token send to email"
        })
        next();

    }
    catch(err){
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({validateBeforeSave: false});

        return next(new AppError("There was an error sending the email. Try again later",500))
    }

})

exports.resetPassword = catchAsync(async(req,res,next)=>{
    //1) Get user based on the token
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {$gt: Date.now()}
    });
    //we are checking if the token is valid and if the token has not expired yet by checking the passwordResetExpires field in the user document


    //2) If token has not expired and there is user, set the new password
    if(!user){
        return next(new AppError('Token is invalid or has expired',400))
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    //3) Update changedPasswordAt property for the user


    //4) Log the user in, send JWT
    token = signToken(user._id),
    res.status(200).json({
        staus:"success",
        token
    })

})