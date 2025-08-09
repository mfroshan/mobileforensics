const { exec } = require('child_process');
const path = require('path');

module.exports.yaraScan = async (filePath) => {
  const yaraRulesPath = path.resolve(__dirname, '../../yara/malware_rules.yar');

  return new Promise((resolve, reject) => {
    exec(`yara "${yaraRulesPath}" "${filePath}"`, (error, stdout, stderr) => {
      if (error) {
        if (error.code === 1) {
          return resolve([]); // No matches
        }
        console.error('YARA stderr:', stderr);
        return reject(stderr || error.message);
      }

      const matches = stdout
        .split('\n')
        .map(line => line.trim().split(' ')[0]) // Get only rule name
        .filter(line => line.length > 0);

      resolve(matches);
    });
  });
};
