import userModel from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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