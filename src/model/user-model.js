import crypto from 'crypto'
import mongoose from 'mongoose';
import validator from 'validator';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'A user must have a name.']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email address.'],
    validate: [validator.isEmail, 'Please provide your valid email address.'],
    unique: true
  },
  photo: {
    type: String,
  },
  role: {
    type: String,
    enum: ['contributer', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please provide a password'],
    validate: {
      // This only works on save and create
      validator: function (el) {
        return this.password === el;
      },
      message: 'Password are not same. '
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  }
});

userSchema.pre('save', async function (next) {
  //  Only run the function if the password was actually modified
  if (!this.isModified('password')) return next();

  //  Hash the password with the cost of 10 processor
  this.password = await bcrypt.hash(this.password, 10);

  // Delete passwordConfirmation
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre(/^find/, function (next) {
  // this points to the current query
  this.find({ active: { $ne: false } });
  next();
})

userSchema.methods.correctPassword = async function (candiatePassword, userPassword) {
  return await bcrypt.compare(candiatePassword, userPassword);
}

userSchema.methods.passwordChangedAfter = (JWTTimeStamp) => {
  if (this.passwordChangedAt) {
    const changedTimeStamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);

    return changedTimeStamp > JWTTimeStamp;
  }

  return false;
}

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const milliSecondsToMinute = 60 * 1000;

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + (10 * milliSecondsToMinute);
  return resetToken;
}

const User = mongoose.model('User', userSchema);

export default User;