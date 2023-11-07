const User = require("../models/User")
const OTP = require("../models/OTP")
const otpGenerator = require("otp-generator")
const bcrypt = require("bcrypt")

//Send OTP
exports.sendOTP = async (req, res) => {

    try {
        //fetch email from request body
        const { email } = req.body;

        //checking if user already exists
        const checkUserPresent = await User.findOne({ email })

        //if exists
        if (checkUserPresent) {
            return res.status(401).json({
                success: false,
                message: "User already registered"
            })
        }

        //generate otp
        var otp = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false
        })
        console.log("OTP generated: ", otp);

        //check for unique otp
        let result = await OTP.findOne({ otp: otp });

        while (result) {
            otp = otpGenerator.generate(6, {
                upperCaseAlphabets: false,
                lowerCaseAlphabets: false,
                specialChars: false
            })
            result = await OTP.findOne({ otp: otp })
        }
        const otpPayload = { email, otp }

        //entry in DB
        const otpBody = await OTP.create(otpPayload)
        console.log(otpBody);

        //return res successful
        res.status(200).json({
            success: true,
            message: "OTP Sent Successfully",
            otp,
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: error.message,
        })
    }

}

//SignUp
exports.signUp = async (req, res) => {

    try {
        //data fetch from request body
        const {
            firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        } = req.body

        //validate
        if (!firstName || !lastName || !email || !password || !confirmPassword || !contactNumber || !otp) {
            return res.status(403).json({
                success: false,
                message: "All fields are required"
            })
        }

        //pass matching
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "Password not matching"
            })
        }

        //check user already exists
        const existingUser = await findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User is already registered"
            })
        }

        //most recent otp
        const recentOtp = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);
        console.log(recentOtp);

        //validate otp
        if (recentOtp.length == 0) {
            //OTP not found
            return res.status(400).json({
                success: false,
                message: "OTP not found"
            })
        } else if (otp !== recentOtp) {
            // Invalid OTP
            return res.status(400).json({
                success: false,
                message: "Invalid OTP"
            })
        }

        //Hash Password
        const hashedPassword = await bcrypt.hash(password, 10)

        //entry in DB
        const profileDetails = await Profile.create({
            gender: null,
            dateOfBirth: null,
            about: null,
            contactNumber: null,
        })

        const user = await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password: hashedPassword,
            accountType,
            additionalDetails: profileDetails,
            image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstname} ${lastname}`
        })

        //return res
        return res.ststus(200).json({
            success: true,
            message: "User registered Successfully",
            user,
        })


    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "User cannot registered. Please try after some time"
        })
    }
}

//Login
exports.login = async (req, res) => {
    try {
        //get data from req body
        const { email, password } = req.body;
        //validate data
        if (!email || !password) {
            return res.status(403).json({
                success: false,
                message: "All fields are required, please try again"
            })
        }

        //check user exist or not
        const user = await User.findOne({ email }).populate("additionalDetails")
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "user is not registered"
            })
        }

        //match pass and generate JWt
        if (await bcrypt.compare(password, user.password)) {
            const payload = {
                email: user.email,
                id: user_id,
                role: user.role,
            }
            const token = jwt.sign(payload, process.env.JWT_SECRET, {
                expiresIn: "1h"
            })
            user.token = token;
            user.password = undefined;

            //create cookie and send res
            const options = {
                expires: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
                httpOnly: true,
            }
            res.cookie("token", token, options).status(200).json({
                success: true,
                token,
                user,
                message: "Logged in Successfully"
            })
        } else {
            return res.status(401).json({
                success: false,
                message: "Password is incorrect"
            })
        }


    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Login Failure, please try again"
        })
    }
}

//Change Password


