const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scan.controller');

router.post('/', scanController.handleScan);
module.exports = router;