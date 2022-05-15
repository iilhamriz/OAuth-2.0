const Users = require('../models/userModel')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const authCtrl = {
    register: async (req, res) => {
        try {
            // Mengambil data dari req.body
            const { fullname, username, email, password, gender } = req.body
            
            // memastikan agar semua input yang kita masukka berupa huruf kecil dan tidak ada spasi
            let newUserName = username.toLowerCase().replace(/ /g, '')

            // melakukan pengecekan apakah nama user sudah terdaftar
            const user_name = await Users.findOne({username: newUserName})
            if(user_name) return res.status(400).json({msg: "This user name already exists."})

            // melakukan pengecekan apakah email user sudah terdaftar
            const user_email = await Users.findOne({email})
            if(user_email) return res.status(400).json({msg: "This email already exists."})

            // validasi password harus lebih dari 6 karakter
            if(password.length < 6)
            return res.status(400).json({msg: "Password must be at least 6 characters."})

            // melakukan hashing password
            const passwordHash = await bcrypt.hash(password, 12)

            const newUser = new Users({
                fullname, username: newUserName, email, password: passwordHash, gender
            })


            // membuat acces token
            const access_token = createAccessToken({id: newUser._id})
            
            // membuat refresh token
            const refresh_token = createRefreshToken({id: newUser._id})

            // menyimpan refresh token kedalam cookie untuk generate acces token dan
            // acces token dapat digunakan agar user yang sudah login tidak perlu login lagi walaupun browser sudah diclose
            res.cookie('refreshtoken', refresh_token, {
                httpOnly: true,
                path: '/api/refresh_token',
                // umur cookie
                maxAge: 30*24*60*60*1000 // 30days
            })

            await newUser.save()

            res.json({
                msg: 'Register Success!',
                access_token,
                user: {
                    ...newUser._doc,
                    password: ''
                }
            })
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    login: async (req, res) => {
        try {
            // Mengambil data dari req.body
            const { email, password } = req.body

            // mencari user dengan email 
            const user = await Users.findOne({email})
            .populate("followers following", "avatar username fullname followers following")

            if(!user) return res.status(400).json({msg: "This email does not exist."})

            // melakukan decrypt password dan compare
            const isMatch = await bcrypt.compare(password, user.password)
            if(!isMatch) return res.status(400).json({msg: "Password is incorrect."})

            // membuat access token
            const access_token = createAccessToken({id: user._id})
            
            // membuat refresh token
            const refresh_token = createRefreshToken({id: user._id})

            // menyimpan refresh token kedalam cookie untuk generate acces token dan
            // acces token dapat digunakan agar user yang sudah login tidak perlu login lagi walaupun browser sudah diclose
            res.cookie('refreshtoken', refresh_token, {
                httpOnly: true,
                path: '/api/refresh_token',
                maxAge: 30*24*60*60*1000 // 30days
            })

            res.json({
                msg: 'Login Success!',
                access_token,
                user: {
                    ...user._doc,
                    password: ''
                }
            })
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    logout: async (req, res) => {
        try {
            res.clearCookie('refreshtoken', {path: '/api/refresh_token'})
            return res.json({msg: "Logged out!"})
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    },
    
    // melakukan generate acces token dari refresh token
    generateAccessToken: async (req, res) => {
        try {
            const rf_token = req.cookies.refreshtoken
            if(!rf_token) return res.status(400).json({msg: "Please login now."})

            jwt.verify(rf_token, process.env.REFRESH_TOKEN_SECRET, async(err, result) => {
                if(err) return res.status(400).json({msg: "Please login now."})

                const user = await Users.findById(result.id).select("-password")
                .populate('followers following', 'avatar username fullname followers following')

                if(!user) return res.status(400).json({msg: "This does not exist."})

                const access_token = createAccessToken({id: result.id})

                res.json({
                    access_token,
                    user
                })
            })
            
        } catch (err) {
            return res.status(500).json({msg: err.message})
        }
    }
}

// fungsi membuat access token
const createAccessToken = (payload) => {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1d'})
}

// fungsi membuat refresh token
const createRefreshToken = (payload) => {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '30d'})
}

module.exports = authCtrl
