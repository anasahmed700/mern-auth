import userModel from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from "../config/emailTemplates.js";

export const register = async (req, res) => {
    const {name, email, password} = req.body;
    if (!name || !email || !password) {
        return res.json({success: false, message: 'Missing details'});
    }

    try {
        const existingUser = await userModel.findOne({email: email});
        if (existingUser) {
            return res.json({success: false, message: 'User already exists'});
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new userModel({email: email, password: hashedPassword, name: name}); 
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000// 7 day
        });

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to our authentication app',
            text: `Hello ${name}, welcome to our authentication app. Your account has been created successfully with email id: ${email}`
        }
        await transporter.sendMail(mailOptions);
        return res.json({success: true, message: 'User registered successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const login = async (req, res) => {
    const {email, password} = req.body;
    if (!email || !password) {
        return res.json({success: false, message: 'Email and password are required'});
    }

    try {
        const user = await userModel.findOne({email});
        if (!user) {
            return res.json({success: false, message: 'User not found'});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.json({success: false, message: 'Invalid credentials'});
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000// 1 day
        });

        return res.json({success: true, message:'Logged in successfully'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });
    
        return res.json({success: true, message: 'Logged out'});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const sendVerifyOtp = async (req, res) => {
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.status(403).json({success: false, message: "Account already verified."});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpiredAt = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Account Verification OTP",
            // text: `Your verification OTP is ${otp}. Please verify your account using this OTP within 24 hours`
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }
        await transporter.sendMail(mailOptions);
        return res.json({success: true, message: 'Verification OTP sent on email.'})
    } catch (error) {
        return res.status(500).json({success: false, message: error.message});
    }
}

export const verifyEmail = async (req, res) => {
    try {
        const {userId, otp} = req.body;
        if (!otp) {
            return res.status(405).json({success: false, message: "Not allowed to verify, please enter the OTP!"})
        }
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({success: false, message: "User not found"});
        }
        if (user.verifyOtp !== otp || user.verifyOtp === '') {
            return res.status(406).json({success: false, message: "Invalid OTP!"})
        }
        if (user.verifyOtpExpiredAt < Date.now()) {
            return res.status(406).json({success: false, message: "OTP is expired!"})
        }
        
        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpiredAt = 0;
        await user.save();

        return res.json({success: true, message: "Email verified successfully!"});
    } catch (error) {
        return res.status(500).json({success: false, message: error.message});
    }
}

export const isAuthenticated = async (req, res) => {
    try {
        return res.json({success: true, message: "Authenticated!"});
    } catch (error) {
        return res.status(500).json({success: false, message: error.message});
    }
}

export const sendResetOtp = async (req, res) => {
    const {email} = req.body;
    if (!email) {
        return res.status(400).json({success: false, message: "Email is required"});
    }
    try {
        const user = await userModel.findOne({email});
        if (!user) {
            return res.status(404).json({success: false, message: "User not found"});
        }
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpiredAt = Date.now() + 15 * 60 * 1000;
        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: "Password reset OTP",
            // text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password`
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }
        await transporter.sendMail(mailOptions);

        return res.json({success: true, message: `The OTP for reset password has been sent to your email address`});
    } catch (error) {
        return res.status(error.status).json({success: false, message: error.message});
    }
}

export const resetPassword = async (req, res) => {
    const {email, otp, newPassword} = req.body;
    if (!email || !otp || !newPassword) {
        return res.status(401).json({success: false, message: "Missing required inputs"});
    }

    try {
        const user = await userModel.findOne({email});
        if (!user) {
            return res.status(404).json({success: false, message: "User not found"});
        }
        if (user.resetOtpExpiredAt < Date.now()) {
            return res.status(406).json({success: false, message: "OTP expired"});
        }
        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.status(406).json({success: false, message: "Invalid OTP!"});
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpiredAt = 0;

        await user.save();
        return res.json({success: true, message: "Password has been reset successfully"});
    } catch (error) {
        return res.status(500).json({success: false, message: error.message});
    }
}