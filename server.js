// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/lk07', { useNewUrlParser: true, useUnifiedTopology: true });

const unverifiedUserSchema = new mongoose.Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    emailVerificationToken: { type: String, default: null }
}, { collection: 'unverified_users' });

unverifiedUserSchema.index({ emailVerificationToken: 1 });

const UnverifiedUser = mongoose.model('UnverifiedUser', unverifiedUserSchema);

const userSchema = new mongoose.Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null }
}, { collection: 'users' });

userSchema.index({ resetPasswordToken: 1, resetPasswordExpires: 1 });

const User = mongoose.model('User', userSchema);

app.use(express.static(path.join(__dirname, 'public')));

const sendAlertAndRedirect = (res, message, redirectUrl) => {
    res.send(`
        <script>
            alert("${message}");
            window.location.href = "${redirectUrl}";
        </script>
    `);
};

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    const { firstname, lastname, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return sendAlertAndRedirect(res, 'Error: Email is already registered', '/register.html');
        }

        const existingUnverifiedUser = await UnverifiedUser.findOne({ email });
        if (existingUnverifiedUser) {
            return sendAlertAndRedirect(res, 'Error: Email is already registered and awaiting verification', '/register.html');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const emailVerificationToken = crypto.randomBytes(32).toString('hex');

        const newUnverifiedUser = new UnverifiedUser({
            firstname,
            lastname,
            email,
            password: hashedPassword,
            emailVerificationToken
        });

        await newUnverifiedUser.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            to: newUnverifiedUser.email,
            from: process.env.EMAIL_USER,
            subject: 'Email Verification',
            text: `Please verify your email by clicking the following link: \n\n
                   http://${req.headers.host}/verify-email/${emailVerificationToken}\n\n`
        };

        await transporter.sendMail(mailOptions);

        sendAlertAndRedirect(res, 'Registration successful! Please check your email for verification.', '/login.html');
    } catch (err) {
        sendAlertAndRedirect(res, 'Error: ' + err.message, '/register.html');
    }
});

app.get('/verify-email/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const unverifiedUser = await UnverifiedUser.findOne({ emailVerificationToken: token });
        if (!unverifiedUser) {
            return sendAlertAndRedirect(res, 'Email verification token is invalid or has expired.', '/register.html');
        }

        const newUser = new User({
            firstname: unverifiedUser.firstname,
            lastname: unverifiedUser.lastname,
            email: unverifiedUser.email,
            password: unverifiedUser.password
        });

        await newUser.save();
        await UnverifiedUser.deleteOne({ email: unverifiedUser.email });

        sendAlertAndRedirect(res, 'Email has been verified successfully!', '/login.html');
    } catch (err) {
        sendAlertAndRedirect(res, 'Error: ' + err.message, '/register.html');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return sendAlertAndRedirect(res, 'Invalid email or password.', '/login.html');
        }

        res.redirect('/dashboard.html');
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('Internal server error');
    }
});


app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return sendAlertAndRedirect(res, 'No account with that email address exists.', '/forgot-password.html');
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expirationTime = Date.now() + 3600000; 

        user.resetPasswordToken = token;
        user.resetPasswordExpires = expirationTime;
        await user.save();

        console.log(`Generated token: ${token}`);
        console.log(`Token expiration time: ${new Date(expirationTime)}`);

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                   Please click on the following link, or paste this into your browser to complete the process:\n\n
                   http://${req.headers.host}/reset/${token}\n\n
                   If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        await transporter.sendMail(mailOptions);

        sendAlertAndRedirect(res, 'An e-mail has been sent to ' + user.email + ' with further instructions.', '/login.html');
    } catch (err) {
        sendAlertAndRedirect(res, 'Error: ' + err.message, '/forgot-password.html');
    }
});

app.get('/reset/:token', async (req, res) => {
    try {
        const token = req.params.token;
        console.log(`Received reset token: ${token}`);

        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            console.log(`Token not found or expired. Token: ${token}`);
            const userWithToken = await User.findOne({ resetPasswordToken: token });
            if (userWithToken) {
                console.log(`Token expiration time in DB: ${new Date(userWithToken.resetPasswordExpires)}`);
            }
            return sendAlertAndRedirect(res, 'Password reset token is invalid or has expired. Please request a new password reset link.', '/forgot-password.html');
        }

        console.log(`Token is valid. Serving reset page for token: ${token}`);
        res.sendFile(path.join(__dirname, 'public', 'reset.html'));
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).send('Error: ' + err.message);
    }
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            console.log(`Token not found or expired when attempting to reset password. Token: ${token}`);
            return sendAlertAndRedirect(res, 'Password reset token is invalid or has expired.', '/forgot-password.html');
        }

        user.password = await bcrypt.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();
        console.log(`Password has been reset for user: ${user.email}`);
        sendAlertAndRedirect(res, 'Password has been reset successfully!', '/login.html');
    } catch (err) {
        console.error('Error resetting password:', err);
        sendAlertAndRedirect(res, 'Error: ' + err.message, '/forgot-password.html');
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
