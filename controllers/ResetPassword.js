const User = require("../models/User")
const mailSender = require("../utils/mailSender")
const bcrypt = require("bcrypt")

//reset pass token
exports.resetPasswordToken = async (req, res) => {
    try {
        //get mail form req body
        const email = req.body.email;
        //check user for this email, validation
        const user = await User.findOne({ email: email })
        if (!user) {
            return res.json({
                success: false,
                message: "your Email is not registered with us"
            })
        }
        //generate token
        const token = crypto.randomUUID();
        //update user by adding token and expiration time
        const updateDetails = await User.findOneAndUpdate(
            { email: email },
            {
                token: token,
                resetPasswordExpires: Date.now() + 5 * 60 * 1000,
            },
            { new: true });
        //create url
        const url = `https://localhost:3000/update-password/${token}`
        //send mail containing the url
        await mailSender(email,
            "Password Reset Link",
            `Password Reset Link : ${url}`);
        //return res
        return res.json({
            success: true,
            message: "Email sent successfully, please check mail to change the password"
        })
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong, please try again"
        })
    }

}


//Reset Password
exports.resetPassword = async (req, res) => {
    try {
        //data fetch
        const { password, confirmPassword, token } = req.body;
        //validation
        if (password !== confirmPassword) {
            return res.json({
                success: false,
                message: "Password not matching"
            })
        }
        //get user details from DB using token
        const userDetails = await User.findOne({ token: token })
        //if no entry- token invalid 
        if (!userDetails) {
            return res.json({
                success: false,
                message: "Token is invalid"
            })
        }
        //check token time
        if (userDetails.resetPasswordExpires < Date.now()) {
            return res.json({
                success: false,
                message: "Token is expired, please regenerate your token"
            })
        }
        //hash pass
        const hashedPassword = await bcrypt.hash(password, 10)
        //pass update
        await User.findOneAndUpdate(
            { token: token },
            { password: hashedPassword },
            { new: true }
        )
        //return res
        return res.status(200).json({
            success: true,
            message: "password reset successfully"
        })
    } catch (error) {
        console.log(error);
        return res.status(200).json({
            success: true,
            message: "Something went wrong, please try again"
        })

    }
}