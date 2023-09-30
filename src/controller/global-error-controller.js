import AppError from '../utilts/app-error.js';

const handleCastErrorDB = err => {
  const message = `Invalid ${err.path} : ${err.value}`;
  return new AppError(message, 400);
}

const handleDuplicateFieldError = err => {
  const value = err.message.match(/(["'])(?:(?=(\\?))\2.)*?\1/)[0];
  const message = `Duplicate value field: ${value}. Please use another value.`;
  return new AppError(message, 400);
}

const handleValidationErrorDB = err => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
}

const handleJWTExpiresError = () => new AppError('Your token has expired. Please login again.', 401);
const handleJWTError = () => new AppError('Invalid token. Please login again.', 401);

const sendErrorProd = (err, res) => {

  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message
    });
  } else {
    console.log(`Error:${err}🤦‍♀️🤦‍♀️`);

    res.status(500).json({
      status: 'error',
      message: 'Internal Server Error'
    });
  }
}

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
    error: err,
    stack: err.stack
  });
}

export default function globalErrorHandler(err, req, res, next) {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else if (process.env.NODE_ENV === 'production') {
    let error = Object.assign(err);

    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldError(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiresError();

    sendErrorProd(error, res);
  }
}
