const express = require('express');
const router = express.Router();
const { handleRegister } = require('../controllers/register.controller');

router.post('/', handleRegister);

module.exports = router;