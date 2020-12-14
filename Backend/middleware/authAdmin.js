const Users = require('../models/userModel');

const authAdmin = async (req, res, next) => {
    try {
        const user = await Users.findOne({_id: req.user.id})

        if(user.role !== 1)
            return res.status(500).json({
                success: false,
                msg: "Sorry!!, You can not access admin resources."
            });

        next()
    } catch (err) {
        return res.status(500).json({
            success: false,
            msg: err.message
        });
    }
}

module.exports = authAdmin