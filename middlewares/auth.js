const jwt = require("jsonwebtoken")
require("dotenv").config();
const User = require("../models/User")

//Auth
exports.auth = async (req, res, next) => {
    try {
        //extract token
        const token = req.cookies.token || req.body.token || req.header("Authorization").replace("bearer ", "")
        //if token missing, return res
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Token is missing"
            })
        }

        //verify token
        try {
            const decode = jwt.verify(token, process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode
        } catch (err) {
            //verification issue
            return res.status(401).json({
                success: false,
                message: "Token is invalid"
            })
        }
        next();

    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Something went wrong while validating the token"
        })
    }
}

//isStudent
exports.isStudent = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Student") {
            return res.status(401).json({
                success: false,
                message: "This is protected route for Students only"
            })
        }
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role connot be verified, please try again"
        })
    }
}

//isInstructor
exports.isInstructor = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Instructor") {
            return res.status(401).json({
                success: false,
                message: "This is protected route for Instructor only"
            })
        }
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role connot be verified, please try again"
        })
    }
}

//isAdmin
exports.isAdmin = async (req, res, next) => {
    try {
        if (req.user.accountType !== "Admin") {
            return res.status(401).json({
                success: false,
                message: "This is protected route for Admin only"
            })
        }
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User role connot be verified, please try again"
        })
    }
}