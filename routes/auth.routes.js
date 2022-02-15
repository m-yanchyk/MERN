const {Router} = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const {check, validationResult} = require('express-validator');
const router = Router();

const User = '../models/User'

// /api/auth/register
router.post('/register',
    [
        check('email', 'Некоректньо введені дані').isEmail(),
        check('password', 'Занадто короткий пароль').isLength({min: 6})
    ],
    async (req, res) => {
    try {

        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректні дані при регістрації'
            })
        }

        const {email, password} = req.body;

        const candidate = await User.findOne({email});

        if(candidate) {
            return res.status(400).json({message: "Такий користувач вже існує"})
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({email, password: hashedPassword});

        await user.save();

        res.status(201).json({message: "Користувач створений"});

    } catch(e) {
        res.status(500).json({message: "Щось пішло не так, спробуйте ще раз..."})
    }
});


// /api/auth/login
router.post('/login',
    [
        check('email', 'Введіть коректний email').normalizeEmail().isEmail(),
        check('password', 'Введіть пароль').exists()
    ],
    async (req, res) => {
    try {

        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Некоректні дані при вході'
            })
        }

        const {email, password} = req.body;

        const user = await User.findOne({email});

        if(!user) {
            res.status(500).json({message: 'Користувач не знайдений'})
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch) {
            return res.status(400).json({message: 'Некоректні дані'})
        }

        const token = jwt.token(
            {userId: user.id},
            config.get('jwtSecret'),
            {expiresIn: '1h'}
        )

        res.json({token, userId: user.id})

    } catch(e) {
        res.status(500).json({message: "Щось пішло не так, спробуйте ще раз..."})
    }
});

module.exports = router;
