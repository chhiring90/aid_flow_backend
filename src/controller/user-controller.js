import User from '../model/user-model.js'
import { getOne } from './factory-controller.js';

export const getUser = getOne(User);