const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const { yaraScan } = require('../services/yaraEngine.js');
const regexScan = require('../services/regexEngine.js');
const mlScore = require('../services/mlEngine.js');
const { scanSqliteDBAdvanced } = require('../services/sqliteScanner');
const { runAleapp } = require('../services/aleappService');
const axios = require('axios');
const FormData = require('form-data')


const prisma = new PrismaClient();
const archiveExtensions = ['.zip', '.tar', '.tar.gz', '.tgz'];

exports.handleScan = async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No file uploaded' });

  const ext = path.extname(file.originalname).toLowerCase();
  const yara = await yaraScan(file.path);
  console.log('YARA Output:', yara);
  const regex = await regexScan(file.path);
  // const ml = await mlScore(file.path);
  // const  aleappResult = await runAleapp(file.path,ext);
 try {
  const formData = new FormData();
  // Add the file with proper metadata
  formData.append('file', fs.createReadStream(file.path), {
    filename: file.originalname,
    contentType: file.mimetype || 'application/octet-stream'
  });

  const response = await axios.post(
    'http://localhost:8000/analyze-chat',
    formData,
    { 
      headers: {
        ...formData.getHeaders(),
        'Content-Length': formData.getLengthSync()
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    }
  );

  ml = response.data.toxicity_percentage || 0;
} catch (err) {
  console.error('FastAPI ML scoring failed:', 
    err.response?.data?.detail || 
    err.response?.data?.message || 
    err.message
  );
  ml = 0;
}

  let sqliteScanResult = null;
  let aleappResult = null;

  if (ext === '.db' || ext === '.sqlite') {
    sqliteScanResult = await scanSqliteDBAdvanced(file.path);
  }

  if (archiveExtensions.includes(ext)) {
    aleappResult = await runAleapp(file.path, ext);
  }

  const riskLevel = ml > 0.7 || yara.length > 0 ? 'HIGH' : 'LOW';

  const record = await prisma.scan.create({
    data: {
      filename: file.originalname,
      yaraMatches: JSON.stringify(yara),
      regexMatches: JSON.stringify(regex),
      mlScore: ml,
      sqliteScan: JSON.stringify(sqliteScanResult),
      aleappScan: JSON.stringify(aleappResult?.reports || []),
      reportUrl: aleappResult?.reportUrl || null, 
      riskLevel,
    },
  });
  console.log(record)
  res.json(record);
};
