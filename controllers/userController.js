const Users = require('../models/userModel');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const sendMail = require('./sendMail');

const {CLIENT_URL} = process.env

const userController = {

    register: async (req, res) => {
        try{
            const {name, email, password} = req.body
            // console.log({name, email, password});

            if(!name || !email || !password)
            return res.status(400).json({
                success: false,
                msg: "Please fill in all fields."
            });

            if(!validateEmail(email))
                return res.status(400).json({
                    success: false,
                    msg: "Please enter valid email address."
            });

            const user = await Users.findOne({email})
            if(user) return res.status(400).json({
                success: false,
                msg: "This email already exists."
            });

            if(password.length < 8)
                return res.status(400).json({
                    success: false,
                    msg: "Password must be at least 8 characters."
            });

            const passwordHash = await bcrypt.hash(password, 15)
            // console.log({passwordHash})

            const newUser = {
                name, email, password: passwordHash
            }
            // console.log({newUser})

            const activation_token = createActivationToken(newUser)
            // console.log({activation_token})

            const url = `${CLIENT_URL}/user/activate/${activation_token}`
            sendMail(email, url, "Verify your email address")

            res.json({
                success: true,
                msg: "Register Success! Please activate your email to start."
            })

        }   catch (err) {
            res.status(500).json({
                success: false,
                msg: err.message
            })
        }
    },

    activateEmail: async (req, res) => {
        try {
            const {activation_token} = req.body
            const user = jwt.verify(activation_token, process.env.ACTIVATION_TOKEN_SECRET)

            // console.log({user});

            const {name, email, password} = user

            const check = await Users.findOne({email})
            if(check) return res.status(400).json({
                success: false,
                msg:"This email already exists."
            });

            const newUser = new Users({
                name, email, password
            })

            await newUser.save()

            res.json({
                success: true,
                msg: "Account has been activated!"
            });

        } catch (err) {
            return res.status(500).json({
                success:false,
                msg: err.message
            });
        }
    },

    login: async (req, res) => {
        try {
            const {email, password} = req.body
            const user = await Users.findOne({email})
            if(!user) return res.status(400).json({
                success: false,
                msg: "This email does not exist."
            });

            const isMatch = await bcrypt.compare(password, user.password)
            if(!isMatch) return res.status(400).json({
                success: false,
                msg: "Password is incorrect."
            });

            const refresh_token = createRefreshToken({id: user._id})
            // console.log({refresh_token})

            res.cookie('refreshtoken', refresh_token, {
                httpOnly: true,
                path: '/user/refresh_token',
                maxAge: 7*24*60*60*1000 // 7 days
            })

            res.json({
                success:true,
                msg: "Login success!"
            });
        } catch (err) {
            return res.status(500).json({
                success:false,
                msg: err.message
            });
        }
    },

    getAccessToken: (req, res) => {
        try {
            const rf_token = req.cookies.refreshtoken
            // console.log({rf_token})

            if(!rf_token) return res.status(400).json({
                success:false,
                msg: "Please login now!"
            });

            jwt.verify(rf_token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
                if(err) return res.status(400).json({
                    success:false,
                    msg: "Please login now!"
                });

                // console.log(user);

                const access_token = createAccessToken({id: user.id})
                res.json({access_token})
            })
        } catch (err) {
            return res.status(500).json({
                success:false,
                msg: err.message
            });
        }
    },

    forgotPassword: async (req, res) => {
        try {
            const {email} = req.body
            const user = await Users.findOne({email})
            if(!user) return res.status(400).json({
                success: false,
                msg: "This email does not exist."
            });

            const access_token = createAccessToken({id: user._id})
            const url = `${CLIENT_URL}/user/reset/${access_token}`

            sendMail(email, url, "Reset your password")
            res.json({
                success: true,
                msg: "Re-send the password, please check your email."
            });
        } catch (err) {
            return res.status(500).json({
                success: false,
                msg: err.message
            });
        }
    },

    resetPassword: async (req, res) => {
        try {
            const {password} = req.body
            console.log(password)
            const passwordHash = await bcrypt.hash(password, 15)

            await Users.findOneAndUpdate({_id: req.user.id}, {
                password: passwordHash
            })

            res.json({
                success: true,
                msg: "Password successfully changed!"
            });

        } catch (err) {
            return res.status(500).json({
                success: true,
                msg: err.message
            });
        }
    },

    getUserInfo: async (req, res) => {
        try {
            const user = await Users.findById(req.user.id).select('-password')

            res.json(user)
        } catch (err) {
            return res.status(500).json({
                success: false,
                msg: err.message
            });
        }
    },

    getUsersAllInfo: async (req, res) => {
        try {
            const users = await Users.find().select('-password')

            res.json(users)
        } catch (err) {
            return res.status(500).json({
                success: false,
                msg: err.message
            });
        }
    },

    logout: async (req, res) => {
        try {
            res.clearCookie('refreshtoken', {path: '/user/refresh_token'})
            return res.json({
                success: true,
                msg: "Logged out."
            });
        } catch (err) {
            return res.status(500).json({
                success: false,
                msg: err.message
            });
        }
    },

    updateUser: async (req, res) => {
        try {
            const {name, avatar} = req.body
            await Users.findOneAndUpdate({_id: req.user.id}, {
                name, avatar
            })

            res.json({
                success: true,
                msg: "Update Success!"
            });

        } catch (err) {
            return res.status(500).json({
                success: false,
                msg: err.message
            });
        }
    },

    updateUsersRole: async (req, res) => {
        try {
            const {role} = req.body

            await Users.findOneAndUpdate({_id: req.params.id}, {
                role
            })

            res.json({
                success: true,
                msg: "Update Success!"
            });
        } catch (err) {
            return res.status(500).json({
                success: true,
                msg: err.message
            });
        }
    },

    deleteUser: async (req, res) => {
        try {
            await Users.findByIdAndDelete(req.params.id)

            res.json({
                success: true,
                msg: "Deleted Success!"
            });
        } catch (err) {
            return res.status(500).json({
                success: true,
                msg: err.message
            });
        }
    },
}

// email validation using RE
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(email);
}

// activation token 
const createActivationToken = (payload) => {
    return jwt.sign(payload, process.env.ACTIVATION_TOKEN_SECRET, {expiresIn: '5m'})
}

// access token
const createAccessToken = (payload) => {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15m'})
}

// refresh token
const createRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '7d'})
}


module.exports = userController