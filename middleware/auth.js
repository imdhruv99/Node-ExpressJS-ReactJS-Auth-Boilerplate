const jwt = require('jsonwebtoken');


const auth = (req, res, next) => {
    try {
        const token = req.header("Authorization");
        // console.log({token})

        if(!token) return res.status(400).json({
            success: false,
            msg: "Invalid Authentication."
        });

        jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if(err) return res.status(400).json({
                success: false,
                msg: "Invalid Authentication."
            });

            req.user = user
            next()
        })
    } catch (err) {
        return res.status(500).json({
            success: false,
            msg: err.message
        });
    }
}

module.exports = auth