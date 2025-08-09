const fs = require('fs');
const path = require('path'); 
const Database = require('better-sqlite3');

const DEFAULT_ROW_LIMIT = 5000;

// Corrected IOC regex patterns
const IOC_PATTERNS = {
  domains: /\b([a-zA-Z0-9.-]+\.(com|net|org|info|biz|ru|cn|io|xyz|gov|edu))\b/gi,

  // Corrected IPv4 regex
  ipv4: /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g,

  ipv6: /\b(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(::1)|(::))\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  emails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  urls: /\bhttps?:\/\/[^\s/$.?#].[^\s]*\b/gi,
  ports: /\bport\s*[:=]\s*\d{1,5}\b/gi,

  // Tightened Android package names regex (common package prefixes)
  android_packages: /\b(?:com|org|net|io|android|androidx|google|facebook|twitter)(\.[a-z0-9_]+)+\b/g,

  android_content_uris: /\bcontent:\/\/[a-zA-Z0-9._\/]+/gi,
  android_file_paths: /\/storage\/emulated\/0\/[^\s'"]+/gi,
  android_app_data_paths: /\/data\/data\/[a-zA-Z0-9._-]+\/[^\s'"]*/gi,
  shared_prefs_files: /[a-zA-Z0-9._-]+_preferences\.xml/gi,
  imei_numbers: /\b\d{15}\b/g,
  imsi_numbers: /\b\d{14,15}\b/g,
  mac_addresses: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g,
  uuids: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b/g,
  firebase_tokens: /\b[A-Za-z0-9\-:_]{140,}\b/g,
  phone_numbers: /\+?\d{10,15}/g,
  geo_coordinates: /\b-?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*-?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g,
  imei: /\b\d{15}\b/g,
  device_serials: /\b[A-Z0-9]{10,20}\b/g,
  advertising_id: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g,
  gsf_id: /\b\d{10,15}\b/g,
  google_oauth_tokens: /\bya29\.[A-Za-z0-9\-_\.]{20,100}\b/g,
  google_api_keys: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  whatsapp_backup_files: /\bmsgstore\.db\.crypt(7|8|9|10|12|14)\b/gi,
  signal_db_files: /\bsignal-[a-z0-9]+\.db\b/gi,
  sqlite_db_files: /\b[a-z0-9_]+\.db\b/gi,
  sms_pdu: /\b[0-9A-F]{10,}\b/g,
  wifi_ssids: /SSID"\s*:\s*"([^"]+)"/gi,
  bluetooth_names: /\bBluetooth\s*Name\s*:\s*([^\r\n]+)/gi,
  base64_keys: /\b[A-Za-z0-9+/=]{40,}\b/g,
  jwt_tokens: /\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g,
  crypto_salts: /\b[a-f0-9]{16,64}\b/gi,
  logcat_timestamps: /\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\b/g,
  android_properties: /\bro\.[a-z0-9._]+\b/g,
  app_secrets: /\b(api_key|secret|token|password|auth)_?[:=]\s*['"][^'"]{8,}['"]/gi,
};

// Suspicious domains set (deduplicated)
const SUSPICIOUS_DOMAINS = new Set([
  'malicious.com',
  'badexample.ru',
  'evil.xyz',
  'phishingsite.net',
  'trojanhost.org',
  'ransomware.biz',
  'spyware.info',
  'hacker-domain.io',
  'darkweb.onion',
  'cmd-and-control.cn',
  'botnetcontroller.io',
  'fakeupdate.com',
  'malware-download.ru',
  'crypto-steal.xyz',
  'fraudulentbank.com',
  'unauthorizedaccess.gov',
  'fakeauthservice.net',
  'exploit-kit.org',
  'zero-day.io',
  'androidrootkit.com',
  'malspam.ru',
  'suspiciousapp.net',
  'insecureapi.com',
  'data-leak.xyz',
  'adware-injector.com',
  'trackerspy.org',
  'spywaretracker.net',
  'backdoorservice.io',
]);

const SUSPICIOUS_KEYWORDS = [
  'password',
  'token',
  'secret',
  'apikey',
  'auth',
  'key',
  'credential',
  'sessionid',
  'access_token',
  'refresh_token',
  'private_key',
  'client_secret',
  'bearer',
  'jwt',
  'oauth',
  'rsa_key',
  'aes_key',
  'encryption_key',
  'decrypt',
  'private_token',
  'cookie',
  'login',
  'passphrase',
  'vault',
  'credential_store',
  'sensitive',
  'confidential',
  'login_token',
  'auth_token',
  'api_key',
  'secret_key',
  'security_token',
  '2fa',
  'mfa',
  'pin',
  'userpass',
  'accesskey',
  'password_hash',
];

const SUSPICIOUS_FILENAMES = [
  'msgstore.db.crypt',
  'wa.db',
  'signal.db',
  'accounts.db',
  'shared_prefs.xml',
  'keyvalue.db',
  'prefs.xml',
  'cookies.sqlite',
  'auth_token.json',
  'tokens.json',
  'credentials.json',
  'secrets.json',
  'private_key.pem',
  'id_rsa',
  'id_dsa',
  'wallet.dat',
  'backup.wallet',
  'sms_backup.xml',
  'call_log.db',
];

const SUSPICIOUS_PACKAGE_PATTERNS = [
  /^com\.evilapp\./,
  /^net\.spyware\./,
  /^org\.malware\./,
  /^com\.hacktool\./,
  /^com\.adware\./,
  /^com\.ransomware\./,
  /^com\.keylogger\./,
  /^com\.botnet\./,
  /^com\.rootkit\./,
  /^com\.fraud\./,
];

// Scan text with IOC patterns
function scanTextForIOCs(text) {
  const results = {};
  for (const [key, regex] of Object.entries(IOC_PATTERNS)) {
    const matches = text.match(regex);
    if (matches && matches.length) {
      results[key] = results[key] || new Set();
      matches.forEach((m) => results[key].add(m));
    }
  }
  return results;
}

// Suspicious domain check
function containsSuspiciousDomain(text) {
  for (const domain of SUSPICIOUS_DOMAINS) {
    if (text.toLowerCase().includes(domain)) return domain;
  }
  return null;
}

// Suspicious keyword check - returns **all** keywords found, not just one
function containsSuspiciousKeywords(text) {
  const foundKeywords = new Set();
  const lowerText = text.toLowerCase();
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (lowerText.includes(keyword)) {
      foundKeywords.add(keyword);
    }
  }
  return Array.from(foundKeywords);
}

function matchesSuspiciousFilename(filename) {
  return SUSPICIOUS_FILENAMES.some(f => filename.toLowerCase().includes(f));
}

function matchesSuspiciousPackageName(text) {
  return SUSPICIOUS_PACKAGE_PATTERNS.some(regex => regex.test(text));
}

async function scanSqliteDBAdvanced(dbPath, rowLimit = DEFAULT_ROW_LIMIT) {
  if (!fs.existsSync(dbPath)) throw new Error(`DB file not found: ${dbPath}`);

  if (matchesSuspiciousFilename(path.basename(dbPath))) {
    console.warn(`Suspicious DB filename detected: ${dbPath}`);
  }

  const db = new Database(dbPath, { readonly: true });

  const tablesStmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table';");
  const tables = tablesStmt.all();

  const aggregatedIOCs = {};
  const tableSummaries = [];

  for (const { name: tableName } of tables) {
    const countStmt = db.prepare(`SELECT COUNT(*) as cnt FROM "${tableName}";`);
    const { cnt: totalRows } = countStmt.get();

    let offset = 0;
    const batchSize = 1000;
    let rowsProcessed = 0;

    while (offset < totalRows && rowsProcessed < rowLimit) {
      const limit = Math.min(batchSize, rowLimit - rowsProcessed);
      const rowsStmt = db.prepare(`SELECT * FROM "${tableName}" LIMIT ? OFFSET ?;`);
      const rows = rowsStmt.all(limit, offset);

      for (const row of rows) {
        for (const colValue of Object.values(row)) {
          if (!colValue) continue;
          let text;
          if (Buffer.isBuffer(colValue)) {
            text = colValue.toString('utf8').replace(/[^\x20-\x7E]/g, '');
          } else if (typeof colValue === 'string') {
            text = colValue;
          } else {
            continue;
          }
          
          // Scan IOCs
          const iocsFound = scanTextForIOCs(text);
          for (const [iocType, matches] of Object.entries(iocsFound)) {
            aggregatedIOCs[iocType] = aggregatedIOCs[iocType] || new Set();
            matches.forEach(m => aggregatedIOCs[iocType].add(m));
          }

          // Suspicious domain detection
          const suspiciousDomain = containsSuspiciousDomain(text);
          if (suspiciousDomain) {
            aggregatedIOCs['suspicious_domains'] = aggregatedIOCs['suspicious_domains'] || new Set();
            aggregatedIOCs['suspicious_domains'].add(suspiciousDomain);
          }

          // Suspicious keywords detection (all found)
          const suspiciousKeywords = containsSuspiciousKeywords(text);
          if (suspiciousKeywords.length > 0) {
            aggregatedIOCs['suspicious_keywords'] = aggregatedIOCs['suspicious_keywords'] || new Set();
            suspiciousKeywords.forEach(k => aggregatedIOCs['suspicious_keywords'].add(k));
          }

          // Suspicious package names
          if (matchesSuspiciousPackageName(text)) {
            aggregatedIOCs['suspicious_packages'] = aggregatedIOCs['suspicious_packages'] || new Set();
            aggregatedIOCs['suspicious_packages'].add(text);
          }
        }
      }

      rowsProcessed += rows.length;
      offset += rows.length;
    }

    tableSummaries.push({
      table: tableName,
      totalRows,
      rowsScanned: rowsProcessed,
    });
  }

  db.close();

  // Format Sets into arrays with counts for output
  const formattedIOCs = {};
  for (const [iocType, matches] of Object.entries(aggregatedIOCs)) {
    formattedIOCs[iocType] = {
      count: matches.size,
      values: Array.from(matches).slice(0, 100), // limit output size
    };
  }

  return {
    summary: {
      tablesScanned: tables.length,
      tableDetails: tableSummaries,
    },
    iocs: formattedIOCs,
  };
}

module.exports = { scanSqliteDBAdvanced };
