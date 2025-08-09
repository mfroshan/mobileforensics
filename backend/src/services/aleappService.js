const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const ALEAPP_PATH = path.resolve(__dirname, '../../ALEAPP/aleapp.py');
const outputBase = path.join(__dirname, '../../reports/aleapp');
const PYTHON_PATH = path.resolve(__dirname, '../../venv/bin/python3');

function getInputType(inputPath) {
  const ext = inputPath.toLowerCase();
  if (ext === '.zip') return 'zip';
  if (ext === '.tar') return 'tar';
  if (ext === '.gz' || ext === '.tgz' || inputPath.endsWith('.tar.gz')) return 'gz';
  return 'fs';
}

function runAleapp(inputFolder, extension) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(inputFolder)) {
      return reject(new Error(`Input folder does not exist: ${inputFolder}`));
    }

    if (!fs.existsSync(outputBase)) {
      fs.mkdirSync(outputBase, { recursive: true });
    }

    const randomSuffix = crypto.randomBytes(3).toString('hex');
    const aleappOutputFolder = path.join(outputBase, `aleapp-${randomSuffix}`);
    fs.mkdirSync(aleappOutputFolder, { recursive: true });

    const inputType = getInputType(extension);
    const command = `"${PYTHON_PATH}" "${ALEAPP_PATH}" -i "${inputFolder}" -o "${aleappOutputFolder}" -t ${inputType}`;

    // console.log(`Executing ALEAPP command: ${command}`);

    exec(command, {
      timeout: 10 * 60 * 1000,
      env: {
        ...process.env,
        PATH: `${path.dirname(PYTHON_PATH)}:${process.env.PATH}`,
        PYTHONPATH: path.dirname(ALEAPP_PATH)
      }
    }, (error, stdout, stderr) => {
      if (error) {
        console.error('ALEAPP Execution Error:', error);
        console.error('STDOUT:', stdout);
        console.error('STDERR:', stderr);
        return reject(new Error(`ALEAPP failed: ${stderr || stdout || error.message}`));
      }

      setTimeout(() => {
        try {
          // Find the report directory
          const reportDirs = fs.readdirSync(aleappOutputFolder)
            .filter(f => f.startsWith('ALEAPP_Reports') && 
                   fs.statSync(path.join(aleappOutputFolder, f)).isDirectory());

          if (reportDirs.length === 0) {
            console.error('No ALEAPP report directories found in:', aleappOutputFolder);
            return resolve({ reports: [], reportUrl: null });
          }

          const reportDir = reportDirs[0];
          const indexPath = path.join(aleappOutputFolder, reportDir, '_HTML', 'index.html');
          console.log("index path:",indexPath)
          if (!fs.existsSync(indexPath)) {
            console.error('Index.html not found at:', indexPath);
            return resolve({ reports: [], reportUrl: null });
          }

          const relativePath = path.relative(
            path.join(__dirname, '../../reports'),
            indexPath
          ).replace(/\\/g, '/');

          const reportUrl = `/reports/${relativePath}`;
          console.log("report url:",reportUrl)

          resolve({
            reports: [],
            reportUrl: `/reports/${relativePath}`
          });
        } catch (err) {
          console.error('Report processing error:', err);
          reject(err);
        }
      }, 2000); // Wait 2 seconds for file operations to complete
    });
  });
}

module.exports = { runAleapp };