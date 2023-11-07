const mongoose = require("mongoose")

const OTPSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now(),
        expires: 5 * 60
    }
})

// function to send emails

async function sendVerificationEmail(email, otp) {
    try {
        const mailResponse = await mailSender(email, "Verification Email from CourseHub", otp);
        console.log("Email Sent Successfully: ", mailResponse);

    } catch (error) {
        console.log("error occured while sending mail: ", error);
        throw error;
    }
}

OTPSchema.pre("save", async function (next) {
    await sendVerificationEmail(this.email, this.otp)
    next();
})

module.exports = mongoose.model("OTP", OTPSchema)