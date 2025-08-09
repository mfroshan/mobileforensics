const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');
const { PrismaClient } = require('@prisma/client');

// Route imports
const scanRoutes = require('./routes/scan.route');
const historyRoutes = require('./routes/history.route');
const registerRoutes = require('./routes/register.route');

dotenv.config();
const app = express();
const prisma = new PrismaClient();
const upload = multer({ dest: 'uploads/' });

// Middleware
app.use(cors());
app.use(bodyParser.json());

const logFilePath = path.join(__dirname, '../src/server.log');

// Middleware to log requests to file
app.use((req, res, next) => {
  const logLine = `${new Date().toISOString()} - ${req.method} ${req.url}\n`;
  fs.appendFile(logFilePath, logLine, err => {
    if (err) console.error('Failed to write log:', err);
  });
  next();
});

const reportsBasePath = path.join(__dirname, '../reports');

app.use('/reports', express.static(reportsBasePath, {
  setHeaders: (res, filePath) => {
    console.log('Serving:', filePath);
  }
}));

// Debug Endpoints
app.get('/debug-report-paths', (req, res) => {
  const aleappPath = path.join(reportsBasePath, 'aleapp');
  try {
    const reports = fs.readdirSync(aleappPath)
      .filter(f => f.startsWith('aleapp-'))
      .map(folder => {
        const fullPath = path.join(aleappPath, folder);
        const reportDir = fs.readdirSync(fullPath).find(f => f.startsWith('ALEAPP_Reports'));
        const indexPath = reportDir ? path.join(fullPath, reportDir, '_HTML', 'index.html') : null;
        return {
          folder,
          exists: indexPath ? fs.existsSync(indexPath) : false,
          physicalPath: indexPath,
          url: indexPath ? `/reports/aleapp/${folder}/${reportDir}/_HTML/index.html` : null
        };
      });
    res.json({
      servingFrom: reportsBasePath,
      availableReports: reports
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Routes
app.use('/scan', upload.single('file'), scanRoutes);
app.use('/history', historyRoutes);
app.use('/register', registerRoutes);

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.use((req, res, next) => {
  console.log('Incoming request:', req.method, req.url);
  next();
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Serving reports from: ${reportsBasePath}`);
  console.log(`Access debug endpoint: http://localhost:${PORT}/debug-report-paths`);
});