import mongoose from 'mongoose';
import dotenv from 'dotenv'
import chalk from 'chalk';

dotenv.config();
import app from './app.js'

const DB = process.env.DB_URI.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);

mongoose
  .connect(DB)
  .then(() => console.log(`${chalk.cyanBright('Database connected successfully 😎')}`))
  .catch(err => console.log(err));


const port = process.env.PORT || 4000;

app.listen(port, () => console.log(`Server listening port ${chalk.green(port)} on ${chalk.blue((process.env.NODE_ENV.toUpperCase()))} mode.${chalk.blue('🕷 🕸')}`));