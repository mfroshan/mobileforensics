const fs = require('fs');

module.exports = async function regexScan(path) {
  const content = fs.readFileSync(path, 'utf8');

  // Enhanced regex patterns for malware detection
  const patterns = {
    // Basic IOCs
    emails: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    ips: /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
    passwords: /\bpass(word)?["']?\s*[:=]\s*["']?.{4,20}["']?/gi,
    email_user: /\b(email|username)["']?\s*[:=]\s*["']?[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/gi,
    urls: /(https?|ftp|tcp|smtp):\/\/[^\s/$.?#].[^\s]*/gi,
    domains: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
    tor_domains: /\.onion\b/gi,
    
    // Malware patterns
    base64: /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/gi,
    hex_strings: /\\x[0-9a-f]{2}/gi,
    suspicious_comments: /(?:\/\/|#|;|--)\s*(?:TODO|FIXME|XXX|MALICIOUS|HACK|EXPLOIT)/gi,
    suspicious_functions: /(?:eval|exec|system|passthru|shell_exec|popen|proc_open|assert|create_function)\s*\(/gi,
    obfuscated_code: /(?:\.|\+|\||\^|\(|\)|\[|\]|\$|\*|\?|\\){5,}/g,
    long_strings: /[^\x20-\x7E]{20,}/g,
    
    // Suspicious Android components
    suspicious_intents: /android\.intent\.action\.(BOOT_COMPLETED|PACKAGE_ADDED|NEW_OUTGOING_CALL)/gi,
    content_provider_abuse: /content:\/\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+/g,

    // Dangerous Android permissions
    dangerous_permissions: /\b(android\.permission\.(READ_SMS|SEND_SMS|RECEIVE_BOOT_COMPLETED|READ_CALL_LOG|WRITE_CALL_LOG|RECORD_AUDIO|CAMERA|WRITE_SETTINGS|SYSTEM_ALERT_WINDOW))\b/gi,

    // Android-specific suspicious Java/Smali methods
    java_exec: /\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|dalvik\.system\.DexClassLoader)\b/gi,
    smali_shell: /invoke-static {.*}, Ljava\/lang\/Runtime;->getRuntime\(\)Ljava\/lang\/Runtime;/g,

    // RAT indicators
    rat_keywords: /\b(?:C2|CommandAndControl|BotNet|KeyLogger|ScreenCapture|RemoteShell|ClientSocket)\b/gi,
  
    // Suspicious Firebase abuse
    firebase_urls: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,

    // Data leakage
    hardcoded_api_keys: /(?:(api[_-]?key|secret|token|auth[_-]?key)[\'"\s:=]+)[\'"]?[a-z0-9_\-]{16,}/gi,
    firebase_api_keys: /AIza[0-9A-Za-z\-_]{35}/g,
    private_keys: /-----BEGIN (RSA|PRIVATE|EC) KEY-----[\s\S]+?-----END \1 KEY-----/g,

    // Networking
    insecure_http: /http:\/\/[^\s'"<>()]+/gi,
    webview_urls: /(?:loadUrl|loadDataWithBaseURL)\s*\(\s*["']http[s]?:\/\/[^\s"']+/gi,

    // Dangerous API usage
    webview_js_interface: /\.addJavascriptInterface\s*\(/gi,
    telephony_manager: /get(Imei|Meid|SimSerialNumber|DeviceId|SubscriberId)/gi,
    sms_interaction: /sendTextMessage|getMessagesFromUri|getAllMessagesFromIcc/gi,
    clipboard_access: /\.getPrimaryClip\s*\(\)/gi,
    file_access: /openFileOutput|openFileInput|getExternalFilesDir/gi,

    // Exploit patterns
    exploit_keywords: /\b(?:Exploit|Payload|Shellcode|PrivEsc|LocalPrivilegeEscalation)\b/gi,
    
    // Ransomware patterns
    ransomware_keywords: /\b(?:Encrypt|Decrypt|Ransom|AES256|RSA2048|Bitcoin|Monero|WalletAddress)\b/gi,
    
    // Script or shell payload indicators (for bash scripts inside APK assets)
    android_shell_abuse: /\b(pm\s+(list|install|uninstall|hide)|am\s+start|setprop|getprop|su\s*-c)\b/gi,

    // PowerShell suspicious patterns
    ps_suspicious: /(?:Start-Process\s+-WindowStyle\s+Hidden|Invoke-Expression|DownloadString|FromBase64String|New-Object\s+Net\.WebClient)\b/gi,
    
    //why the use windows API Abuse??
    // Windows API abuse
    dangerous_apis: /\b(?:VirtualAlloc|CreateRemoteThread|WriteProcessMemory|SetWindowsHookEx|RegSetValue)\b/gi,
    
    // Obfuscation techniques
    char_code_obfuscation: /(?:String\.fromCharCode|chr\(|char\(|\\.{2,4})/gi,
    
    // Anti-analysis
    anti_emulator: /Build\.(MODEL|BRAND|DEVICE|PRODUCT|HARDWARE)\s*==\s*["'](?:generic|sdk|emulator)/gi,
    anti_debug: /Debug\.isDebuggerConnected\(\)|android\.os\.Debug/gi,

    // Obfuscation
    xor_obfuscation: /\bchar\s*[\[\]]\s*\w+\s*=\s*{\s*(?:0x[0-9a-f]{2},\s*){5,}\s*}/gi,
    b64_large_strings: /(?:[A-Za-z0-9+/]{4}){20,}/gi,
    string_from_charcode: /String\.fromCharCode\s*\((\d+,?\s*){3,}\)/gi,

    // File paths
    temp_file_use: /\/data\/local\/tmp\/[^\s"']+/gi,
    uncommon_paths: /\/sdcard\/\.hidden\/[^\s"']+/gi,

    // Permissions
    permission_patterns: /android\.permission\.(RECORD_AUDIO|READ_SMS|WRITE_SETTINGS|READ_CALL_LOG|INTERNET|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES)/gi,

    // Payloads
    dex_loader: /DexClassLoader\s*\(/gi,
    reflection_abuse: /Class\.forName|getMethod|invoke/gi,
    intent_abuse: /Intent\.setComponent|Intent\.setClassName/gi,

    // Root/payload
    root_commands: /\b(su\s*-c|busybox|whoami|which\s+su|chmod\s+777)\b/gi,
    native_exec: /Runtime\.getRuntime\(\)\.exec\s*\(["'][^"']+/gi,
    load_native_libs: /System\.loadLibrary\s*\(\s*["'][^"']+["']\s*\)/gi,


    jwt_tokens: /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b/g,
    google_tokens: /\bya29\.[0-9A-Za-z\-_]+\b/g,
    api_keys: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    fb_access_token: /\bEAACEdEose0cBA[0-9A-Za-z]+/g,
    refresh_tokens: /\brefresh[_-]?token["']?\s*[:=]\s*["']?[A-Za-z0-9\-_\.]{20,}/gi,

    reflection: /invoke-(virtual|static) \{.*\}, Ljava\/lang\/reflect\/Method;->invoke/g,
    su_checks: /const-string [vp]\d+, "su"/g,
    root_detection: /Landroid\/os\/Build;->TAGS:.*test-keys/g,
    dynamic_class_loading: /Ljava\/lang\/ClassLoader;->loadClass/g,
    native_libs: /System\.loadLibrary\("[^"]+"\)/g,
    exec_commands: /Runtime\.getRuntime\(\)\.exec\(["'][^"']+["']\)/g,

    bangcle: /libsecexe\.so|libSecShell\.so/g,
    dexprotector: /libDexProtector\.so|com\.licel\.dexprotector/g,
    protector_strings: /"This application is protected by"/g,
    encrypted_dex_marker: /classes.*\.jar\.encrypted/g,
    assets_payload: /assets\/.*\.bin|assets\/payload\.dex/g,
    anti_debug: /android.os.Debug|isDebuggerConnected|android.os.SystemProperties/g,
    
    webview_bridge: /window\.webkit\.messageHandlers/g,
    js_eval: /eval\(["'`](.*)["'`]\)/gi,
    js_iframe_inject: /document\.write\(\s*['"]<iframe/gi,
    crypto_miner: /coinhive|miner\.js|cryptonight/gi,
    malicious_endpoints: /(http|https):\/\/[^\s]+\/malware[^\s]*/gi,
    
    // Script droppers
    script_droppers: /(?:certutil\s+-decode|bitsadmin\s+\/transfer|msiexec\s+\/i|rundll32\s+[^,]+,\s*[^\s)]+)/gi

  };

  const results = {};
  
  // Scan for each pattern
  for (const [name, regex] of Object.entries(patterns)) {
    const matches = [...content.matchAll(regex)].map(r => r[0]);
    if (matches.length > 0) {
      results[name] = matches;
    }
  }

  // Additional heuristic checks
  results.heuristics = {
    high_entropy_strings: detectHighEntropyStrings(content),
    suspicious_combinations: checkSuspiciousCombinations(results)
  };

  return results;
};

// Helper function to detect high entropy strings (potential encryption/compression)
function detectHighEntropyStrings(content) {
  const strings = content.match(/[A-Za-z0-9+/=]{20,}/g) || [];
  return strings.filter(str => {
    const entropy = calculateShannonEntropy(str);
    return entropy > 4.5; // Threshold for high entropy
  });
}

// Helper function to calculate Shannon entropy
function calculateShannonEntropy(str) {
  const len = str.length;
  const frequencies = Array(256).fill(0);
  
  for (let i = 0; i < len; i++) {
    frequencies[str.charCodeAt(i)]++;
  }
  
  return frequencies.reduce((sum, f) => {
    if (f > 0) {
      const p = f / len;
      sum -= p * Math.log2(p);
    }
    return sum;
  }, 0);
}

// Helper function to detect suspicious combinations of indicators
function checkSuspiciousCombinations(results) {
  const alerts = [];
  
  // Combination: URLs + executable downloads
  if (results.urls && results.script_droppers) {
    alerts.push('URLs combined with script dropper patterns detected');
  }
  
  // Combination: Obfuscation + suspicious functions
  if ((results.obfuscated_code || results.char_code_obfuscation) && 
      results.suspicious_functions) {
    alerts.push('Obfuscation combined with dangerous functions detected');
  }
  
  // Combination: RAT keywords + network indicators
  if (results.rat_keywords && (results.urls || results.ips || results.domains)) {
    alerts.push('RAT indicators combined with network IOCs detected');
  }
  
  return alerts.length > 0 ? alerts : ['No suspicious combinations detected'];
}