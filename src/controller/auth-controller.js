import { promisify } from 'util';
import crypto from 'crypto'
import jwt from 'jsonwebtoken'

import User from '../model/user-model.js'
import catchAsync from '../utilts/catch-async.js'
import AppError from '../utilts/app-error.js'

const signToken = id => {
  return jwt.sign(
    { id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN });
}

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_EXPIRES_IN * 24 * 60 * 60 * 1000,
    ),
    httpOnly: false
  }

  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token);

  user.password = undefined;
  res.status(statusCode).json({
    status: 'success',
    token,
    data: { user }
  });
}

export const signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    passwordChangeAt: req.body.passwordChangeAt,
    role: req.body.role
  });

  createSendToken(newUser, 201, res);
});

export const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  //  check it email and password exists
  if (!email || !password) {
    next(new AppError('Please provide email and password', 400));
  }

  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password'), 401);
  }

  //  if everything is ok send token to the client
  createSendToken(user, 200, res);
});

export const protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it's there
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('You are not logged in . Please log in to get access.', 401))
  }

  // 2) Verification tokens
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user exist 
  const currentUser = await User.findById(decoded.id);

  if (!currentUser) {
    return next(new AppError('The user belonging to this token does not exist', 401));
  }

  // 4) Check if user changed password after the token was issued
  if (currentUser.passwordChangedAfter(decoded.iat)) {
    return next(new AppError('User recently changed password. Please login again', 401));
  }

  req.user = currentUser;
  next();
});

export const forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError('There is no user with this email', 404));
  }

  // 2) Generate random test tokens
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send Email to the Users
  try {
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetpassword/${resetToken}`;
    // await new Email(user, resetURL).sendResetPassword();

    res.status(200).json({
      status: 'success',
      message: 'Token sent to Email'
    });

  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was error Sending Email. Please try again later!', 500))
  }
});

export const passwordReset = catchAsync(async (req, res, next) => {
  // 1) Get bases on hash token
  const hashToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
  const user = await User.findOne({ passwordResetToken: hashToken, passwordResetExpires: { $gt: Date.now() } });

  // if token is not expired, and there is user set new password
  if (!user) {
    return next(new AppError('Token is invalid and has expired', 400));
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // Update passwordChangedAt property
  createSendToken(user, 200, res, req);
});

export const updatePassword = catchAsync(async (req, res, next) => {

  // 1) Get user from collection
  const user = await User.findById(req.params.id).select('+password');

  // 2) Check if posted current password is correct
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError('Your password in incorrect', 401));
  }

  // 3) if so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // User findByIdAndUpdate will not work as intented

  createSendToken(user, 200, res, req);
});

export const getMe = catchAsync(async (req, res, next) => {
  res.status(200)
    .json({
      status: "success",
      data: {
        data: req.user
      }
    });
})