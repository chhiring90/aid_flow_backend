import express from 'express'
import { signup, login, forgotPassword, getMe, protect } from '../controller/auth-controller.js'

const router = express.Router();

//  Mounting Router
// Authentication Routers
router.route('/signup').post(signup);
router.route('/login').post(login);
router.route('/forgotpassword').post(forgotPassword);
router.route('/me').get(protect, getMe)

// router.route('/resetpassword/:token').patch(authController.passwordReset);
// router.route('/updatepassword/:id').patch(authController.updatePassword);

// User Routers

// router.route('/').get(authController.protect, userController.getAllUsers);

// router.route('/:id')
//   .get(userController.getUser)
//   .patch(userController.updateUser)
//   .delete(userController.deleteUser);

export default router;