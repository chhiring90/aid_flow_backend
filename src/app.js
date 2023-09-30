import express from 'express'
import morgan from 'morgan';
import cors from 'cors';

import AuthRouter from './router/auth-router.js'
import globalErrorHandler from './controller/global-error-controller.js';
import AppError from './utilts/app-error.js';

const app = express();

app.use(cors());
// Access-Control-Allow-Origin *

app.options('*', cors());

// 1) Middleware
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

app.use(express.json());
// 2) Routes
app.use("/api/v1/auth", AuthRouter);

// Error
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server`, 404));
});

app.use(globalErrorHandler);


export default app;
