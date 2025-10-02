// Preload script para exposición de API segura
const { contextBridge, ipcRenderer } = require('electron');

// Exponer APIs seguras al proceso renderer
contextBridge.exposeInMainWorld('electronAPI', {
  // Funciones relacionadas con la seguridad
  scanVulnerabilities: () => ipcRenderer.invoke('scan-vulnerabilities'),
  generatePassword: (options) => ipcRenderer.invoke('generate-password', options),
  monitorNetwork: () => ipcRenderer.invoke('monitor-network'),
  forensicAnalysis: (filePath) => ipcRenderer.invoke('forensic-analysis', filePath),
  
  // Funciones de bóveda de contraseñas
  addPasswordToVault: (passwordData) => ipcRenderer.invoke('add-password-to-vault', passwordData),
  removePasswordFromVault: (passwordId) => ipcRenderer.invoke('remove-password-from-vault', passwordId),
  getAllPasswords: () => ipcRenderer.invoke('get-all-passwords'),
  searchPasswords: (query) => ipcRenderer.invoke('search-passwords', query),
  exportVault: (format) => ipcRenderer.invoke('export-vault', format),
  importVault: (importData) => ipcRenderer.invoke('import-vault', importData),
  getVaultStats: () => ipcRenderer.invoke('get-vault-stats'),
  recalculatePasswordStrengths: () => ipcRenderer.invoke('recalculate-password-strengths'),
  
  // Funciones del sistema
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  getSecurityStatus: () => ipcRenderer.invoke('get-security-status'),
  
  // Funciones del keylogger
  startKeylogger: () => ipcRenderer.invoke('start-keylogger'),
  stopKeylogger: () => ipcRenderer.invoke('stop-keylogger'),
  getKeyloggerStatus: () => ipcRenderer.invoke('get-keylogger-status'),
  exportKeyloggerLogs: (format) => ipcRenderer.invoke('export-keylogger-logs', format),
  clearKeyloggerLogs: () => ipcRenderer.invoke('clear-keylogger-logs'),
  
  // Funciones del antivirus
  startAntivirusScan: (scanType) => ipcRenderer.invoke('start-antivirus-scan', scanType),
  stopAntivirusScan: () => ipcRenderer.invoke('stop-antivirus-scan'),
  scanFile: (filePath) => ipcRenderer.invoke('scan-file', filePath),
  scanFolders: (folderPaths) => ipcRenderer.invoke('scan-folders', folderPaths),
  getAntivirusStatus: () => ipcRenderer.invoke('get-antivirus-status'),
  getAntivirusStats: () => ipcRenderer.invoke('get-antivirus-stats'),
  updateAntivirusDatabase: () => ipcRenderer.invoke('update-antivirus-database'),
  
  // Funciones del analizador forense
  analyzeFile: (filePath, analysisType) => ipcRenderer.invoke('analyze-file', filePath, analysisType),
  analyzeFolder: (folderPath, analysisType) => ipcRenderer.invoke('analyze-folder', folderPath, analysisType),
  getFileHash: (filePath, hashType) => ipcRenderer.invoke('get-file-hash', filePath, hashType),
  extractMetadata: (filePath) => ipcRenderer.invoke('extract-metadata', filePath),
  detectMalware: (filePath) => ipcRenderer.invoke('detect-malware', filePath),
  
  // Antivirus Testing APIs
  generateTestFiles: () => ipcRenderer.invoke('generate-test-files'),
  testEicarDetection: () => ipcRenderer.invoke('test-eicar-detection'),
  generateAdvancedTestFiles: () => ipcRenderer.invoke('generate-advanced-test-files'),
  generateAggressiveTestFiles: () => ipcRenderer.invoke('generate-aggressive-test-files'),
  testRealAntivirusDetection: () => ipcRenderer.invoke('test-real-antivirus-detection'),
  diagnoseAntivirusStatus: () => ipcRenderer.invoke('diagnose-antivirus-status'),
  scanFileWithVirusTotal: (filePath) => ipcRenderer.invoke('scan-file-with-virustotal', filePath),
  scanUrlWithVirusTotal: (url) => ipcRenderer.invoke('scan-url-with-virustotal', url),
  scanDomainWithVirusTotal: (domain) => ipcRenderer.invoke('scan-domain-with-virustotal', domain),
  scanIpWithVirusTotal: (ipAddress) => ipcRenderer.invoke('scan-ip-with-virustotal', ipAddress),
  generateRealMalwareTests: () => ipcRenderer.invoke('generate-real-malware-tests'),
    comprehensiveAntivirusDiagnostic: () => ipcRenderer.invoke('comprehensive-antivirus-diagnostic'),
    deleteThreats: () => ipcRenderer.invoke('delete-threats'),
    clearThreatHistory: () => ipcRenderer.invoke('clear-threat-history'),
  
  // Funciones de análisis del sistema
  fullSystemAnalysis: () => ipcRenderer.invoke('full-system-analysis'),
  generateSystemReport: () => ipcRenderer.invoke('generate-system-report'),
  getProcessList: () => ipcRenderer.invoke('get-process-list'),
  getNetworkConnections: () => ipcRenderer.invoke('get-network-connections'),
  
  // Funciones de gestión de reportes
  getAnalysisReports: () => ipcRenderer.invoke('get-analysis-reports'),
  exportAnalysisReport: (reportId, format) => ipcRenderer.invoke('export-analysis-report', reportId, format),
  clearAnalysisLogs: () => ipcRenderer.invoke('clear-analysis-logs'),
  getLastAnalysis: () => ipcRenderer.invoke('get-last-analysis'),
  getAnalysisStats: () => ipcRenderer.invoke('get-analysis-stats'),
  
  // Actualizaciones en tiempo real del keylogger
  onKeyloggerUpdate: (callback) => ipcRenderer.on('keylogger-update', callback),
  
  // Actualizaciones en tiempo real del antivirus
  onAntivirusUpdate: (callback) => ipcRenderer.on('antivirus-update', callback),
  onAntivirusProgress: (callback) => ipcRenderer.on('antivirus-progress', callback),
  testProgress: () => ipcRenderer.invoke('test-progress'),
  
  // Actualizaciones en tiempo real del análisis
  onAnalysisUpdate: (callback) => ipcRenderer.on('analysis-update', callback),
  
  // Eventos
  onSecurityAlert: (callback) => ipcRenderer.on('security-alert', callback),
  onNetworkEvent: (callback) => ipcRenderer.on('network-event', callback),
  
  // File operations
  showOpenDialog: (options) => ipcRenderer.invoke('show-open-dialog', options),
  showSaveDialog: (options) => ipcRenderer.invoke('show-save-dialog', options),
  
  // App data operations
  getAppData: () => ipcRenderer.invoke('get-app-data'),
  updateScanData: (scanData) => ipcRenderer.invoke('update-scan-data', scanData),
  
  // Eliminar eventos
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel)
});

// Inicializar la aplicación
window.addEventListener('DOMContentLoaded', () => {
  console.log('Script de preload cargado exitosamente');
  
  // Verificar si estamos en un contexto seguro
  if (window.isSecureContext) {
    console.log('Ejecutándose en contexto seguro');
  }
});
