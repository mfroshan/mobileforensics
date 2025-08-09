const express = require('express');
const multer = require('multer');
const fileController = require('../controllers/fileController');

const router = express.Router();
const upload = multer({ dest: 'backend/uploads/' });

router.post('/upload', upload.single('file'), fileController.uploadAndScan);

const formData = new FormData();
formData.append('file', selectedFile);

fetch('/api/upload', {
  method: 'POST',
  body: formData,
})
  .then(res => res.json())
  .then(data => {
    if (data.status === 'malware') {
      alert('Malware detected: ' + data.matches.join(', '));
    } else {
      alert('File is clean!');
    }
  });

module.exports = router;