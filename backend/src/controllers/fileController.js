const path = require('path');
const yaraEngine = require('../services/yaraEngine');

exports.uploadAndScan = async (req, res) => {
  try {
    // Assuming you're using multer and the file is saved as req.file
    const filePath = req.file.path;
    const yaraResult = await yaraEngine.yaraScan(filePath);

    if (yaraResult.length > 0) {
      // Malware detected
      return res.json({ status: 'malware', matches: yaraResult });
    } else {
      // No malware detected
      return res.json({ status: 'clean' });
    }
  } catch (err) {
    return res.status(500).json({ error: err.toString() });
  }
};