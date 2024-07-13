const User = require("./../models/userModel");
const catchAsync = require("./../utils/catchAsync")
const AppError = require("./../utils/appError")

const filerObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if(allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;

}
//Here we are filtering out the fields that are not allowed to be updated. filerObj is a function that filters out the fields that are not allowed to be updated. Here obj, ...allowedFields are the arguments that are passed to the function. Then we are creating a new object called newObj. Then we are iterating over the object and checking if the allowedFields array includes the element. If it does then we are adding that element to the newObj object. Then we are returning the newObj object.

exports.getAllUsers = catchAsync(async(req, res) => {
  const users = await User.find()
  res.status(200).json({
    status: "success",
    users
  })
});

exports.updateMe = catchAsync(async(req,res,next)=>{
  //1) Create error if user POSTs password data
  if(req.body.password || req.body.passwordConfirm){
    return next(new AppError('This route is not for password updates. Please use /updateMyPassword',400))
  }

  //2) Update user document
  const filteredBody = filerObj(req.body, 'name', 'email');
  //Here we are filtering out the fields that are not allowed to be updated. filerObj is a function that filters out the fields that are not allowed to be updated. Here req.body, 'name', 'email' are the arguments that are passed to the function.
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {new: true, runValidators: true});
  //Here we can use findByIdAndUpdate because we are not dealing with passwords and any other sensitive data

  res.status(200).json({
    status: 'success',
    data:{
      user: updatedUser
    }
  })
})

exports.deleteMe = catchAsync(async(req,res,next)=>{
  await User.findByIdAndUpdate(req.user.id, {active: false});

  res.status(204).json({
    status: 'success',
    data: null
  })
})
exports.getUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};
exports.createUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};
exports.updateUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};
exports.deleteUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'This route is not yet defined!'
  });
};
