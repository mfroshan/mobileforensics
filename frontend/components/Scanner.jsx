import { useState, useEffect } from "react";
import {
  Shield,
  Upload,
  FileText,
  Mail,
  Globe,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Zap,
  Activity,
  Search,
  History,
  Download,
  Trash2,
  Eye,
  Calendar,
  Brain,
  Database,
  FileArchive,
  ExternalLink,
} from "lucide-react";
import { useRouter } from "next/navigation";

const YARA_RULE_SETS = [
  {
    name: "Malware Signatures",
    description: "Scanning for known malware patterns",
    color: "text-red-400",
  },
  {
    name: "Suspicious Network Activity",
    description: "Analyzing network communications",
    color: "text-orange-400",
  },
  {
    name: "Phishing & Social Engineering",
    description: "Detecting phishing attempts",
    color: "text-yellow-400",
  },
  {
    name: "Cryptocurrency Miners",
    description: "Checking for hidden mining code",
    color: "text-purple-400",
  },
  {
    name: "System File Integrity",
    description: "Verifying system file authenticity",
    color: "text-blue-400",
  },
];

const uploadScan = async (file, onProgress) => {
  onProgress({ currentRule: 0, progress: 10, scanning: true });

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch("http://localhost:4000/scan", {
      method: "POST",
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    onProgress({ currentRule: -1, progress: 100, scanning: false });
    return [data];
  } catch (error) {
    onProgress({ currentRule: -1, progress: 0, scanning: false });
    throw error;
  }
};

export default function Scanner() {
  const [file, setFile] = useState(null);
  const [fileType, setFileType] = useState("all");
  const [result, setResult] = useState([]);
  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);
  const [scanProgress, setScanProgress] = useState({
    currentRule: -1,
    progress: 0,
    scanning: false,
  });
  const router=useRouter();

  const handleUpload = async () => {
    if (!file) return;
    try {
      const res = await uploadScan(file, setScanProgress);
      const scanResults = Array.isArray(res) ? res : [res];

      setResult(scanResults);

      // Add to history with unique ID and timestamp
      const historyEntry = scanResults.map((item) => ({
        ...item,
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        uploadedAt: new Date().toISOString(),
      }));

      // Add new items to the beginning and limit to 10
      setHistory((prev) => [...historyEntry, ...prev].slice(0, 10));
    } catch (error) {
      console.error("Scan failed:", error);
      alert(`Scan failed: ${error.message}. Please check if the backend server is running on http://localhost:4000`);
    }
  };

  const safeParse = (val, fallback) => {
    if (!val || val === "null" || val === null) return fallback;
    if (typeof val === "object") return val;
    try {
      const parsed = JSON.parse(val);
      return typeof parsed === "object" ? parsed : fallback;
    } catch {
      return fallback;
    }
  };

  // Function to determine if file is malware based on any findings
  const isFileMalware = (item) => {
    const yaraMatches = safeParse(item.yaraMatches, []);
    const aleappMatches = safeParse(item.aleappScan, []);
    const regexMatches = safeParse(item.regexMatches, {});
    
    // Check for any malicious indicators
    const hasYaraMatches = yaraMatches.length > 0;
    const hasAleappFindings = aleappMatches.length > 0;
    const hasSuspiciousIPs = regexMatches.ips?.length > 0;
    const hasSuspiciousURLs = regexMatches.urls?.length > 0;
    const hasSuspiciousDomains = regexMatches.domains?.length > 0;
    const hasObfuscation = regexMatches.char_code_obfuscation?.length > 0;
    const hasLongStrings = regexMatches.long_strings?.length > 0;
    const hasHighEntropyStrings = regexMatches.heuristics?.high_entropy_strings?.length > 0;
    const hasSuspiciousCombinations = regexMatches.heuristics?.suspicious_combinations?.some(
      combo => combo !== "No suspicious combinations detected"
    );
    
    return hasYaraMatches || hasAleappFindings || hasSuspiciousIPs || hasSuspiciousURLs || 
           hasSuspiciousDomains || hasObfuscation || hasLongStrings || hasHighEntropyStrings || 
           hasSuspiciousCombinations;
  };

  // Function to get automatic risk level based on findings
  const getAutoRiskLevel = (item) => {
    const yaraMatches = safeParse(item.yaraMatches, []);
    const mlScore = item.mlScore || 0;
    
    // High risk if YARA matches are found OR ML score is very high
    if (yaraMatches.length > 0 || mlScore > 0.8) {
      return "HIGH";
    }
    
    // Medium risk for moderate ML scores or other suspicious indicators
    if (mlScore > 0.4 || isFileMalware(item)) {
      return "MEDIUM";
    }
    
    return "LOW";
  };

  const parsedResults = result.map((item) => {
    const parsed = {
      ...item,
      yaraMatches: safeParse(item.yaraMatches, []),
      aleappScan: safeParse(item.aleappScan, []),
      sqliteScan: safeParse(item.sqliteScan, null),
      regexMatches: safeParse(item.regexMatches, {
        ips: [],
        urls: [],
        domains: [],
        long_strings: [],
        char_code_obfuscation: [],
        heuristics: { high_entropy_strings: [], suspicious_combinations: [] },
      }),
      scanStats: item.scanStats || {
        totalRules: 0,
        matchedRules: 0,
        scanDuration: "00:00:00",
      },
    };
    
    // Override risk level based on findings
    parsed.riskLevel = getAutoRiskLevel(parsed);
    return parsed;
  });

  const parsedHistory = history.map((item) => {
    const parsed = {
      ...item,
      yaraMatches: safeParse(item.yaraMatches, []),
      aleappScan: safeParse(item.aleappScan, []),
      sqliteScan: safeParse(item.sqliteScan, null),
      regexMatches: safeParse(item.regexMatches, {
        ips: [],
        urls: [],
        domains: [],
        long_strings: [],
        char_code_obfuscation: [],
        heuristics: { high_entropy_strings: [], suspicious_combinations: [] },
      }),
      scanStats: item.scanStats || {
        totalRules: 0,
        matchedRules: 0,
        scanDuration: "00:00:00",
      },
    };
    
    // Override risk level based on findings for history items too
    parsed.riskLevel = getAutoRiskLevel(parsed);
    return parsed;
  });

  const getRiskColor = (riskLevel) => {
    switch (riskLevel?.toUpperCase()) {
      case "HIGH":
        return "border-red-500 bg-red-900/20";
      case "MEDIUM":
        return "border-yellow-500 bg-yellow-900/20";
      case "LOW":
        return "border-green-500 bg-green-900/20";
      default:
        return "border-gray-600 bg-gray-800/50";
    }
  };

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel?.toUpperCase()) {
      case "HIGH":
        return <XCircle className="w-5 h-5 text-red-400" />;
      case "MEDIUM":
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      case "LOW":
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      default:
        return <Shield className="w-5 h-5 text-gray-400" />;
    }
  };

  const getTotalMatches = (item) => {
    const yaraMatches = safeParse(item.yaraMatches, []);
    const aleappMatches = safeParse(item.aleappScan, []);
    const regexMatches = safeParse(item.regexMatches, {});
    
    return (
      (yaraMatches?.length || 0) +
      (aleappMatches?.length || 0) +
      (regexMatches.ips?.length || 0) +
      (regexMatches.urls?.length || 0) +
      (regexMatches.domains?.length || 0) +
      (regexMatches.long_strings?.length || 0) +
      (regexMatches.char_code_obfuscation?.length || 0) +
      (regexMatches.heuristics?.high_entropy_strings?.length || 0) +
      (regexMatches.heuristics?.suspicious_combinations?.filter(combo => combo !== "No suspicious combinations detected").length || 0)
    );
  };

  const downloadReport = (item) => {
    const report = {
      filename: item.filename,
      scanDate: new Date(item.uploadedAt).toLocaleString(),
      riskLevel: item.riskLevel,
      mlScore: item.mlScore,
      scanStats: item.scanStats,
      yaraMatches: safeParse(item.yaraMatches, []),
      aleappScan: safeParse(item.aleappScan, []),
      sqliteScan: safeParse(item.sqliteScan, null),
      regexMatches: safeParse(item.regexMatches, {}),
      reportUrl: item.reportUrl,
      totalMatches: getTotalMatches(item),
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-report-${item.filename}-${
      new Date().toISOString().split("T")[0]
    }.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadAllHistory = () => {
    const allReports = parsedHistory.map((item) => ({
      filename: item.filename,
      scanDate: new Date(item.uploadedAt).toLocaleString(),
      riskLevel: item.riskLevel,
      mlScore: item.mlScore,
      scanStats: item.scanStats,
      yaraMatches: safeParse(item.yaraMatches, []),
      aleappScan: safeParse(item.aleappScan, []),
      sqliteScan: safeParse(item.sqliteScan, null),
      regexMatches: safeParse(item.regexMatches, {}),
      reportUrl: item.reportUrl,
      totalMatches: getTotalMatches(item),
    }));

    const blob = new Blob([JSON.stringify(allReports, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `all-scan-history-${
      new Date().toISOString().split("T")[0]
    }.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const clearHistory = () => {
    if (confirm("Are you sure you want to clear all scan history?")) {
      setHistory([]);
      setShowHistory(false);
    }
  };

  const viewHistoryItem = (item) => {
    setSelectedHistoryItem(item);
    setResult([item]);
    setShowHistory(false);
  };

  const acceptedTypes = {
    all: "*",
    pdf: ".pdf",
    db: ".db,.sqlite",
    zip: ".zip,.tar,.gz,.tgz,.apk",
    txt: ".txt",
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-cyan-400 mr-3" />
            <h1 className="text-4xl font-bold">Forensics Mobile</h1>
          </div>
          <p className="text-gray-400">Advanced Malware Detection System with YARA Rules & ML Analysis</p>
        </div>

        {/* YARA Status Indicator */}
        <div className="bg-gray-800 rounded-lg p-4 mb-6 border border-blue-500/30">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Zap className="w-6 h-6 text-blue-400" />
              <div>
                <h3 className="font-semibold text-blue-300">YARA Engine Status</h3>
                <p className="text-sm text-gray-400">
                  Rules loaded: <code className="text-cyan-400">backend/yara/malware_rules.yar</code>
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-green-400 text-sm font-medium">Active</span>
            </div>
          </div>
          <div className="mt-3 text-xs text-gray-500">
            <p>• <code>detect_malicious_mobile_apps</code> - Scans for malicious Android applications</p>
            <p>• Multi-rule scanning enabled for comprehensive threat detection</p>
            <p>• If YARA matches show empty, check: file extraction, rule syntax, and scanner integration</p>
          </div>
        </div>

        {/* File Selection */}
        <div className="bg-gray-800 rounded-lg p-6 mb-6">
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Select File for Analysis
            </label>
            <div className="flex items-center space-x-4 flex-wrap gap-2">
              <select
                value={fileType}
                onChange={(e) => setFileType(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-300"
              >
                <option value="all">All Files</option>
                <option value="pdf">PDF</option>
                <option value="db">SQLite / DB</option>
                <option value="zip">Archive Files (ZIP/APK)</option>
                <option value="txt">Text Files</option>
              </select>

              <input
                type="file"
                accept={acceptedTypes[fileType]}
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                className="flex-1 min-w-0 px-3 py-2 bg-gray-700 border border-gray-600 rounded text-gray-300 file:bg-cyan-600 file:text-white"
              />

              <button
                onClick={handleUpload}
                disabled={!file || scanProgress.scanning}
                className="bg-cyan-600 hover:bg-cyan-700 px-6 py-2 rounded disabled:opacity-50 whitespace-nowrap"
              >
                {scanProgress.scanning ? (
                  <span className="flex items-center">
                    <Activity className="w-4 h-4 mr-2 animate-pulse" />
                    Scanning...
                  </span>
                ) : (
                  <span className="flex items-center">
                    <Upload className="w-4 h-4 mr-2" />
                    Start Scan
                  </span>
                )}
              </button>

              <button
                onClick={() => setShowHistory(!showHistory)}
                className="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded flex items-center whitespace-nowrap"
              >
                <History className="w-4 h-4 mr-2" />
                History ({history.length})
              </button>

              <button className="bg-green-600 hover:bg-green-700 px-6 py-2 rounded text-white whitespace-nowrap" onClick={()=>router.push("/whatsappupload")}>
                Upload WhatsApp File
              </button>
            </div>
          </div>
        </div>

        {/* History Panel */}
        {showHistory && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold flex items-center">
                <History className="w-6 h-6 mr-3 text-blue-400" />
                Scan History
              </h3>
              <div className="flex space-x-2">
                <button
                  onClick={downloadAllHistory}
                  className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded flex items-center text-sm"
                  disabled={history.length === 0}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download All
                </button>
                <button
                  onClick={clearHistory}
                  className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded flex items-center text-sm"
                  disabled={history.length === 0}
                >
                  <Trash2 className="w-4 h-4 mr-2" />
                  Clear History
                </button>
              </div>
            </div>

            {history.length === 0 ? (
              <div className="text-center py-8">
                <History className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">No scan history available</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                {parsedHistory.map((item) => (
                  <div
                    key={item.id}
                    className={`p-4 rounded-lg border-l-4 ${getRiskColor(
                      item.riskLevel
                    )}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <FileText className="w-6 h-6 text-gray-400" />
                        <div>
                          <h4 className="font-semibold">{item.filename}</h4>
                          <div className="flex items-center space-x-4 text-sm text-gray-400">
                            <span className="flex items-center">
                              <Calendar className="w-3 h-3 mr-1" />
                              {new Date(item.uploadedAt).toLocaleDateString()}
                            </span>
                            <span>{getTotalMatches(item)} matches</span>
                            <span className="flex items-center">
                              {getRiskIcon(item.riskLevel)}
                              <span className="ml-1 capitalize">
                                {item.riskLevel} Risk
                              </span>
                            </span>
                            {item.yaraMatches.length > 0 && (
                              <span className="bg-red-600 px-2 py-1 rounded text-xs font-bold">
                                YARA: {item.yaraMatches.length}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => viewHistoryItem(item)}
                          className="bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded text-sm flex items-center"
                        >
                          <Eye className="w-3 h-3 mr-1" />
                          View
                        </button>
                        <button
                          onClick={() => downloadReport(item)}
                          className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-sm flex items-center"
                        >
                          <Download className="w-3 h-3 mr-1" />
                          Download
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {scanProgress.scanning && (
          <div className="bg-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center mb-4">
              <Activity className="w-6 h-6 text-cyan-400 mr-3 animate-pulse" />
              <h3 className="text-xl font-semibold">
                Multi-Engine Scanning in Progress
              </h3>
            </div>
            <div className="mb-6">
              <div className="flex justify-between text-sm text-gray-400 mb-2">
                <span>Overall Progress</span>
                <span>{scanProgress.progress}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3">
                <div
                  className="bg-cyan-500 h-3 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress.progress}%` }}
                ></div>
              </div>
            </div>

            <div className="space-y-3">
              {YARA_RULE_SETS.map((ruleSet, index) => (
                <div key={index} className="flex items-center space-x-4">
                  <div className="w-6 h-6 flex items-center justify-center">
                    {index < scanProgress.currentRule ? (
                      <CheckCircle className="w-5 h-5 text-green-400" />
                    ) : index === scanProgress.currentRule ? (
                      <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                    ) : (
                      <div className="w-4 h-4 border-2 border-gray-600 rounded-full"></div>
                    )}
                  </div>
                  <div className="flex-1">
                    <div
                      className={`font-medium ${
                        index <= scanProgress.currentRule
                          ? ruleSet.color
                          : "text-gray-500"
                      }`}
                    >
                      {ruleSet.name}
                    </div>
                    <div className="text-sm text-gray-500">
                      {ruleSet.description}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {parsedResults.length > 0 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-bold flex items-center">
                <Search className="w-6 h-6 mr-3 text-cyan-400" />
                Scan Results
              </h2>
              <div className="flex space-x-2">
                <button
                  onClick={() => setResult([])}
                  className="bg-gray-600 hover:bg-gray-700 px-4 py-2 rounded flex items-center"
                >
                  Close Results
                </button>
                <button
                  onClick={() => downloadReport(parsedResults[0])}
                  className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded flex items-center"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download Report
                </button>
              </div>
            </div>

            {parsedResults.map((item) => (
              <div
                key={item.id}
                className={`bg-gray-800 rounded-lg border-l-4 overflow-hidden ${getRiskColor(
                  item.riskLevel
                )}`}
              >
                <div className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center space-x-3">
                      <FileText className="w-8 h-8 text-gray-400" />
                      <div>
                        <h3 className="text-xl font-bold">{item.filename}</h3>
                        <p className="text-sm text-gray-400">
                          Scanned: {new Date(item.uploadedAt).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div
                        className={`flex items-center space-x-2 px-4 py-2 rounded-full border ${getRiskColor(
                          item.riskLevel
                        )}`}
                      >
                        {getRiskIcon(item.riskLevel)}
                        <span className="font-bold uppercase text-sm">
                          {item.riskLevel} Risk
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4 mb-6 text-center">
                    <div className="bg-gray-700 rounded p-3">
                      <div className="text-2xl font-bold text-cyan-400">
                        {item.scanStats.totalRules}
                      </div>
                      <div className="text-sm text-gray-400">Rules Scanned</div>
                    </div>
                    <div className="bg-gray-700 rounded p-3">
                      <div className="text-2xl font-bold text-yellow-400">
                        {getTotalMatches(item)}
                      </div>
                      <div className="text-sm text-gray-400">Total Matches</div>
                    </div>
                    <div className="bg-gray-700 rounded p-3">
                      <div className="text-2xl font-bold text-green-400">
                        {item.scanStats.scanDuration}
                      </div>
                      <div className="text-sm text-gray-400">Scan Time</div>
                    </div>
                  </div>

                  <div className="grid md:grid-cols-2 gap-6">
                    {/* YARA Matches - Enhanced Display */}
                    {item.yaraMatches.length > 0 ? (
                      <div className="bg-red-800 rounded p-4 border border-red-500/30 col-span-full">
                        <h4 className="font-bold text-red-300 mb-3 flex items-center">
                          <Zap className="w-5 h-5 mr-2" />
                          🚨 YARA MALWARE DETECTED ({item.yaraMatches.length} rules matched)
                        </h4>
                        <div className="bg-red-900/50 p-3 rounded mb-3">
                          <p className="text-red-200 text-sm font-medium mb-2">
                            ⚠️ CRITICAL: This file has been flagged by YARA malware detection rules!
                          </p>
                          <p className="text-red-300 text-xs">
                            The following rules from <code>backend/yara/malware_rules.yar</code> have matched:
                          </p>
                        </div>
                        <div className="space-y-2">
                          {item.yaraMatches.map((ruleName, idx) => (
                            <div
                              key={`yara-${idx}`}
                              className="bg-red-900/40 border border-red-600/30 px-3 py-2 rounded text-sm text-red-200 flex items-center justify-between"
                            >
                              <div className="flex items-center">
                                <AlertTriangle className="w-4 h-4 mr-2 text-red-400" />
                                <code className="font-mono">{ruleName}</code>
                              </div>
                              <span className="bg-red-600 px-2 py-1 rounded text-xs font-bold">
                                MATCH
                              </span>
                            </div>
                          ))}
                        </div>
                        <div className="mt-3 p-2 bg-red-900/30 rounded border border-red-600/20">
                          <p className="text-red-200 text-xs">
                            <strong>Recommendation:</strong> Quarantine this file immediately. 
                            YARA rule matches indicate potential malware presence.
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="bg-green-800 rounded p-4 border border-green-500/30">
                        <h4 className="font-bold text-green-300 mb-3 flex items-center">
                          <CheckCircle className="w-5 h-5 mr-2" />
                          YARA Scan Results
                        </h4>
                        <div className="bg-green-900/40 border border-green-600/30 px-3 py-2 rounded text-sm text-green-200">
                          ✅ No YARA rule matches found - No known malware signatures detected
                        </div>
                        <div className="mt-2 text-xs text-green-300">
                          Scanned against: <code>backend/yara/malware_rules.yar</code>
                        </div>
                      </div>
                    )}

                    {/* ALEAPP Scan Results */}
                    {item.aleappScan && item.aleappScan.length > 0 && (
                      <div className="bg-purple-800 rounded p-4 border border-purple-500/30">
                        <h4 className="font-bold text-purple-300 mb-3 flex items-center">
                          <Database className="w-5 h-5 mr-2" />
                          ALEAPP Analysis ({item.aleappScan.length})
                        </h4>
                        <div className="space-y-2">
                          {item.aleappScan.map((finding, idx) => (
                            <div
                              key={`aleapp-${idx}`}
                              className="bg-purple-900/40 border border-purple-600/30 px-3 py-2 rounded text-sm text-purple-200"
                            >
                              {finding}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* SQLite Scan Results */}
                    {item.sqliteScan && (
                      <div className="bg-blue-800 rounded p-4 border border-blue-500/30">
                        <h4 className="font-bold text-blue-300 mb-3 flex items-center">
                          <Database className="w-5 h-5 mr-2" />
                          SQLite Analysis
                        </h4>
                        <div className="bg-blue-900/40 border border-blue-600/30 px-3 py-2 rounded text-sm text-blue-200">
                          {JSON.stringify(item.sqliteScan, null, 2)}
                        </div>
                      </div>
                    )}

                    {/* Domains */}
                    {item.regexMatches.domains?.length > 0 && (
                      <div className="bg-red-700 rounded p-4 border border-red-500/30">
                        <h4 className="font-bold text-red-300 mb-3 flex items-center">
                          <Globe className="w-5 h-5 mr-2" />
                          Suspicious Domains ({item.regexMatches.domains.length})
                        </h4>
                        <div className="space-y-2">
                          {item.regexMatches.domains.map((domain, idx) => (
                            <div
                              key={`domain-${idx}`}
                              className="bg-red-900/40 border border-red-600/30 px-3 py-2 rounded text-sm text-red-200"
                            >
                              {domain}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Long Strings */}
                    {item.regexMatches.long_strings?.length > 0 && (
                      <div className="bg-red-700 rounded p-4 border border-red-500/30">
                        <h4 className="font-bold text-red-300 mb-3 flex items-center">
                          <FileText className="w-5 h-5 mr-2" />
                          Suspicious Long Strings ({item.regexMatches.long_strings.length})
                        </h4>
                        <div className="space-y-2 max-h-32 overflow-y-auto">
                          {item.regexMatches.long_strings.slice(0, 5).map((str, idx) => (
                            <div
                              key={`string-${idx}`}
                              className="bg-red-900/40 border border-red-600/30 px-3 py-2 rounded text-sm text-red-200 font-mono break-all"
                            >
                              {str.length > 100 ? `${str.substring(0, 100)}...` : str}
                            </div>
                          ))}
                          {item.regexMatches.long_strings.length > 5 && (
                            <div className="text-sm text-red-300 text-center">
                              ... and {item.regexMatches.long_strings.length - 5} more
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Character Code Obfuscation */}
                    {item.regexMatches.char_code_obfuscation?.length > 0 && (
                      <div className="bg-red-700 rounded p-4 border border-red-500/30">
                        <h4 className="font-bold text-red-300 mb-3 flex items-center">
                          <AlertTriangle className="w-5 h-5 mr-2" />
                          Character Code Obfuscation ({item.regexMatches.char_code_obfuscation.length})
                        </h4>
                        <div className="space-y-2 max-h-32 overflow-y-auto">
                          {item.regexMatches.char_code_obfuscation.slice(0, 10).map((code, idx) => (
                            <div
                              key={`code-${idx}`}
                              className="bg-red-900/40 border border-red-600/30 px-3 py-2 rounded text-sm text-red-200 font-mono break-all"
                            >
                              {code.length > 50 ? `${code.substring(0, 50)}...` : code}
                            </div>
                          ))}
                          {item.regexMatches.char_code_obfuscation.length > 10 && (
                            <div className="text-sm text-gray-400 text-center">
                              ... and {item.regexMatches.char_code_obfuscation.length - 10} more
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Heuristics */}
                    {(item.regexMatches.heuristics?.high_entropy_strings?.length > 0 || 
                      (item.regexMatches.heuristics?.suspicious_combinations?.length > 0 && 
                       item.regexMatches.heuristics.suspicious_combinations.some(combo => combo !== "No suspicious combinations detected"))) && (
                      <div className="bg-red-700 rounded p-4 border border-red-500/30">
                        <h4 className="font-bold text-red-300 mb-3 flex items-center">
                          <Brain className="w-5 h-5 mr-2" />
                          Heuristic Analysis - Malicious Patterns Detected
                        </h4>
                        
                        {item.regexMatches.heuristics.high_entropy_strings?.length > 0 && (
                          <div className="mb-4">
                            <h5 className="text-sm font-semibold text-red-200 mb-2">
                              High Entropy Strings ({item.regexMatches.heuristics.high_entropy_strings.length})
                            </h5>
                            <div className="space-y-1">
                              {item.regexMatches.heuristics.high_entropy_strings.slice(0, 3).map((str, idx) => (
                                <div
                                  key={`entropy-${idx}`}
                                  className="bg-red-900/40 border border-red-600/30 px-2 py-1 rounded text-xs text-red-100 font-mono break-all"
                                >
                                  {str.length > 80 ? `${str.substring(0, 80)}...` : str}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {item.regexMatches.heuristics.suspicious_combinations?.filter(combo => combo !== "No suspicious combinations detected").length > 0 && (
                          <div>
                            <h5 className="text-sm font-semibold text-red-200 mb-2">
                              Suspicious Combinations ({item.regexMatches.heuristics.suspicious_combinations.filter(combo => combo !== "No suspicious combinations detected").length})
                            </h5>
                            <div className="space-y-1">
                              {item.regexMatches.heuristics.suspicious_combinations
                                .filter(combo => combo !== "No suspicious combinations detected")
                                .map((combo, idx) => (
                                <div
                                  key={`combo-${idx}`}
                                  className="bg-red-900/40 border border-red-600/30 px-2 py-1 rounded text-xs text-red-100"
                                >
                                  {combo}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Report URL */}
                    {item.reportUrl && (
                      <div className="bg-blue-700 rounded p-4 border border-blue-500/30 col-span-full">
                        <h4 className="font-bold text-blue-300 mb-3 flex items-center">
                          <FileArchive className="w-5 h-5 mr-2" />
                          Detailed Analysis Report
                        </h4>
                        <div className="flex items-center space-x-3">
                          <div className="flex-1">
                            <p className="text-sm text-blue-200 mb-2">
                              A comprehensive analysis report has been generated with detailed findings.
                            </p>
                            <p className="text-xs text-blue-300 font-mono break-all">
                              {item.reportUrl}
                            </p>
                          </div>
                          <a
                            href={item.reportUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded flex items-center text-sm font-medium transition-colors"
                          >
                            <ExternalLink className="w-4 h-4 mr-2" />
                            View Report
                          </a>
                        </div>
                      </div>
                    )}

                    {/* No Matches Found */}
                    {getTotalMatches(item) === 0 && !item.reportUrl && (
                      <div className="bg-green-800 rounded p-4 border border-green-500/30 col-span-full">
                        <h4 className="font-bold text-green-300 mb-3 flex items-center">
                          <CheckCircle className="w-5 h-5 mr-2" />
                          Clean File - No Threats Detected
                        </h4>
                        <p className="text-green-200 text-sm">
                          This file has passed all security checks. No malicious patterns, suspicious domains, 
                          or obfuscated code were detected during the analysis.
                        </p>
                        <div className="mt-2 text-xs text-green-300">
                          ✅ YARA Rules: No matches found<br/>
                          ✅ Pattern Analysis: Clean<br/>
                          ✅ Heuristic Scan: No threats detected
                        </div>
                      </div>
                    )}
                  </div>

                  {/* ML Analysis Summary */}
                  <div className="mt-6 bg-gray-700 rounded-lg p-4">
                    <h4 className="font-bold text-gray-300 mb-3 flex items-center">
                      <Brain className="w-5 h-5 mr-2" />
                      Machine Learning Analysis Summary
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="text-center">
                        <div className="text-sm text-gray-400 mb-1">Confidence Score</div>
                        <div className={`text-2xl font-bold ${
                          item.mlScore >= 0.7 ? 'text-red-400' :
                          item.mlScore >= 0.4 ? 'text-yellow-400' : 'text-green-400'
                        }`}>
                          {(item.mlScore * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-400 mb-1">Risk Classification</div>
                        <div className={`text-lg font-semibold ${
                          item.riskLevel === 'HIGH' ? 'text-red-400' :
                          item.riskLevel === 'MEDIUM' ? 'text-yellow-400' : 'text-green-400'
                        }`}>
                          {item.riskLevel}
                        </div>
                      </div>
                      <div className="text-center">
                        <div className="text-sm text-gray-400 mb-1">Recommendation</div>
                        <div className={`text-sm font-medium ${
                          item.riskLevel === 'HIGH' ? 'text-red-400' :
                          item.riskLevel === 'MEDIUM' ? 'text-yellow-400' : 'text-green-400'
                        }`}>
                          {item.riskLevel === 'HIGH' ? 'Quarantine File' :
                           item.riskLevel === 'MEDIUM' ? 'Review Carefully' : 'Safe to Use'}
                        </div>
                      </div>
                    </div>
                    <div className="mt-3 text-sm text-gray-400">
                      {item.yaraMatches.length > 0 && (
                        <div className="mb-2 p-2 bg-red-900/30 rounded border border-red-600/20">
                          <strong className="text-red-300">YARA Alert:</strong> {item.yaraMatches.length} malware signature(s) detected. 
                          This overrides ML score and sets risk to HIGH.
                        </div>
                      )}
                      {item.riskLevel === 'HIGH' && item.yaraMatches.length === 0 && 
                        "High-risk file detected. Multiple indicators suggest this file may contain malicious content. Immediate action recommended."}
                      {item.riskLevel === 'MEDIUM' && 
                        "Medium-risk file detected. Some suspicious patterns found. Further investigation recommended before use."}
                      {item.riskLevel === 'LOW' && 
                        "Low-risk file detected. No significant threats identified. File appears to be safe for normal use."}
                    </div>
                  </div>

                  {/* Troubleshooting Section for Empty YARA Results */}
                  {item.yaraMatches.length === 0 && (
                    <div className="mt-6 bg-yellow-800/30 rounded-lg p-4 border border-yellow-600/30">
                      <h4 className="font-bold text-yellow-300 mb-3 flex items-center">
                        <AlertTriangle className="w-5 h-5 mr-2" />
                        YARA Troubleshooting
                      </h4>
                      <div className="text-sm text-yellow-200 space-y-2">
                        <p><strong>If YARA should have matched but didn't:</strong></p>
                        <ul className="list-disc list-inside space-y-1 text-xs text-yellow-100 ml-4">
                          <li>Check if the file is being extracted from ZIP before scanning</li>
                          <li>Verify YARA rule syntax in <code>backend/yara/malware_rules.yar</code></li>
                          <li>Ensure rule conditions match the file type being scanned</li>
                          <li>Check backend logs for YARA execution errors</li>
                          <li>Verify the scanner is processing the correct file path</li>
                        </ul>
                        <p className="text-xs mt-2">
                          <strong>Rule Status:</strong> <code>detect_malicious_mobile_apps</code> loaded from <code>backend/yara/malware_rules.yar</code>
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {!scanProgress.scanning && parsedResults.length === 0 && (
          <div className="text-center py-12">
            <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400 text-lg">
              {history.length > 0
                ? "Select a file to scan or view your scan history"
                : "Upload a file to begin comprehensive security analysis"}
            </p>
            <p className="text-gray-500 text-sm mt-2">
              Our multi-engine scanner uses YARA rules, ALEAPP analysis, SQLite inspection, 
              and machine learning to provide thorough threat detection.
            </p>
            <div className="mt-4 p-3 bg-blue-900/20 rounded border border-blue-600/30 max-w-md mx-auto">
              <p className="text-blue-300 text-xs">
                <strong>YARA Engine:</strong> Ready with malware detection rules<br/>
                <strong>Supported Files:</strong> APK, ZIP, PDF, SQLite, Text files
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}