const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require("bcryptjs")
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'A user must have a name'],
        min: 3,
        max: 255
    },
    email: {
        type: String,
        required: [true, 'A user must have an email'],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    photo: {
        type: String
        // required: true,
    },
    role:{
        type: String,
        enum:['user','guide','lead-guide','admin'],
        default: 'user'
    },
    password: {
        type: String,
        required: [true, 'A user must have a password'],
        minLength: 8,
        select: false
        // max: 1024
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Confirm your password'],
        minLength: 8,
        validate:{
            //This only works on CREATE and SAVE!!!
            validator: function(el){
                return el === this.password;
            },
            message: 'Passwords are not the same'
        }
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    active:{
        type: Boolean,
        default: true,
        select: false
    
    }
});

userSchema.pre('save', async function(next){
    //Only run this function if password was actually modified
    if(!this.isModified('password')) return next();
    //Hash the password with cost of 12
    this.password = await bcrypt.hash(this.password, 12);
    //Delete passwordConfirm field
    this.passwordConfirm = undefined;
    next();
});

userSchema.pre('save', function(next){
    if(!this.isModified('password') || this.isNew) return next();
    //this.isNew is used to check if the document is new or not
    this.passwordChangedAt = Date.now() - 1000;
    //1000 is used to make sure that the token is created after the password is changed
    next();

});

userSchema.pre(/^find/, function(next){ //"/^find/" is a regular expression that means that any string that starts with find will be executed, which means that any query that starts with find will be executed
    //this points to the current query
    this.find({active: {$ne: false}});
    next();
})

userSchema.methods.correctPassword = async function(candidatePassword,userPassword){
    //we got candidate password form login and user passowrnd form signup
    return await bcrypt.compare(candidatePassword,userPassword);
    //Here the candidate password is not hashed but the user password is hashed. So without the compare fucntion there is no other way to know that these passowrd are equal.
}

userSchema.methods.changedPasswordAfter = function(JWTTimestamp){
    if(this.passwordChangedAt){
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime()/1000,10);
        //the above line is to convert the passwordChangedAt to seconds
        //parseInt is used to convert the string to number
        console.log(changedTimestamp,JWTTimestamp)
        return JWTTimestamp < changedTimestamp;
    }
    //False means not changed
    return false;
}

userSchema.methods.correctPasswordResetToken = function(){
    const resetToken = crypto.randomBytes(32).toString('hex');
    //basically we are creating a random token and then hashing it
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    //the above line is to hash the token and then return it
    this.passwordResetExpires = Date.now() + 10*60*1000;
    //the above line is to set the expiration time of the token to 10 minutes

    return resetToken;
    //we are returning the unhashed token to send it to the user via email and then hash it again when the user sends it back to us to compare it with the hashed token in the database to reset the password.
}

module.exports = mongoose.model('User', userSchema);
