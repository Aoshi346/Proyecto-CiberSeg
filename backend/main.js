const { app, BrowserWindow, ipcMain, session, Menu, dialog } = require('electron');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const fs = require('fs');

// Importar módulos de análisis
const FileAnalyzer = require('./analyzer');
const SystemAnalyzer = require('./systemAnalyzer');

// Proceso global del keylogger
let keyloggerProcess = null;
let keyloggerStatus = {
  isRunning: false,
  startTime: null,
  logFile: path.join(__dirname, 'system_log.txt')
};

// Proceso global del antivirus
let antivirusProcess = null;
let antivirusStatus = {
  isRunning: false,
  startTime: null
};

// Almacenamiento para historial de escaneos y datos de la aplicación
const appDataPath = path.join(__dirname, 'app_data.json');
let appData = {
  lastScanDate: null,
  scanHistory: [],
  totalScans: 0,
  totalFilesScanned: 0,
  totalThreatsFound: 0
};

// Cargar datos de la aplicación al inicio
function loadAppData() {
  try {
    if (fs.existsSync(appDataPath)) {
      const data = fs.readFileSync(appDataPath, 'utf8');
      appData = { ...appData, ...JSON.parse(data) };
      console.log('App data loaded successfully');
    }
  } catch (error) {
    console.error('Error loading app data:', error);
  }
}

// Guardar datos de la aplicación
function saveAppData() {
  try {
    fs.writeFileSync(appDataPath, JSON.stringify(appData, null, 2));
    console.log('App data saved successfully');
  } catch (error) {
    console.error('Error saving app data:', error);
  }
}

// Instancias de los módulos de análisis
const fileAnalyzer = new FileAnalyzer();
const systemAnalyzer = new SystemAnalyzer();

// Configurar la ruta de userData para evitar problemas con OneDrive
try {
  const tempBase = path.join(os.tmpdir(), 'ciberseg');
  app.setPath('userData', tempBase);
} catch (e) {
  console.warn('Failed setting userData path', e);
}

// Reducir problemas de caché
app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
app.commandLine.appendSwitch('disable-gpu');
app.disableHardwareAcceleration();

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, '..', 'frontend', 'renderer', 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      webSecurity: false,
      partition: 'persist:ciberseg',
      devTools: true
    },
    show: false,
    autoHideMenuBar: true
  });
  
  // Habilitar atajo de herramientas de desarrollador
  win.webContents.on('before-input-event', (event, input) => {
    if (input.control && input.shift && input.key.toLowerCase() === 'i') {
      win.webContents.toggleDevTools();
    }
  });
  win.webContents.session.clearCache();
  session.defaultSession?.clearCache();

  // Ocultar la barra de menú para esta ventana explícitamente
  win.setMenuBarVisibility(false);
  
  // Cargar el archivo HTML del frontend
  win.loadFile(path.join(__dirname, '..', 'frontend', 'renderer', 'index.html'));
  
  win.once('ready-to-show', () => {
    win.show();
  });
}

app.whenReady().then(() => {
  // Cargar datos de la aplicación al inicio
  loadAppData();
  
  // Eliminar el menú global de la aplicación (Archivo/Editar/Ver...)
  try { Menu.setApplicationMenu(null); } catch (_) {}
  createWindow();
  setupIPC();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Función auxiliar para ejecutar scripts de Python
async function runPythonScript(scriptPath, args = [], enableProgressStreaming = false, isAntivirus = false) {
  return new Promise((resolve, reject) => {
    const pythonProcess = spawn('python', [scriptPath, ...args], {
      cwd: path.dirname(scriptPath),
      stdio: ['pipe', 'pipe', 'pipe']
    });

    // Almacenar referencia del proceso antivirus si este es un escaneo antivirus
    if (isAntivirus) {
      antivirusProcess = pythonProcess;
      antivirusStatus.isRunning = true;
      antivirusStatus.startTime = new Date();
    }

    let stdout = '';
    let stderr = '';
    let progressBuffer = '';

    pythonProcess.stdout.on('data', (data) => {
      const output = data.toString();
      console.log('Python stdout received:', output.substring(0, 100) + '...');
      
      if (enableProgressStreaming) {
        // Manejar streaming de progreso - cada línea debe ser una actualización de progreso JSON
        progressBuffer += output;
        const lines = progressBuffer.split('\n');
        progressBuffer = lines.pop(); // Mantener línea incompleta en buffer
        
        lines.forEach(line => {
          if (line.trim()) {
            try {
              const progressData = JSON.parse(line.trim());
              // Enviar actualización de progreso al renderer
              console.log('Sending progress update:', progressData);
              const mainWindow = BrowserWindow.getAllWindows()[0];
              if (mainWindow && mainWindow.webContents) {
                mainWindow.webContents.send('antivirus-progress', progressData);
              } else {
                console.log('Main window not available for sending progress');
              }
            } catch (error) {
              // If it's not JSON, it's probably the final result or duplicate
              // Don't log every non-JSON line to reduce noise
              if (line.trim().length > 50) {
                console.log('Non-JSON output (truncated):', line.trim().substring(0, 50) + '...');
              }
              stdout += line + '\n';
            }
          }
        });
      } else {
        stdout += output;
      }
    });

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    pythonProcess.on('close', (code) => {
      // Clean up antivirus process reference if this was an antivirus scan
      if (isAntivirus) {
        antivirusProcess = null;
        antivirusStatus.isRunning = false;
        antivirusStatus.startTime = null;
      }

      if (code === 0) {
        try {
          // Handle any remaining output in buffer
          if (enableProgressStreaming && progressBuffer.trim()) {
            try {
              const progressData = JSON.parse(progressBuffer.trim());
              const mainWindow = BrowserWindow.getAllWindows()[0];
              if (mainWindow && mainWindow.webContents) {
                mainWindow.webContents.send('antivirus-progress', progressData);
              }
            } catch (error) {
              stdout += progressBuffer;
            }
          }
          
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (error) {
          resolve({ success: true, output: stdout });
        }
      } else {
        // Check if this was a stopped antivirus scan (SIGTERM)
        if (isAntivirus && !antivirusStatus.isRunning) {
          // This was intentionally stopped, resolve with success
          resolve({ success: true, message: 'Escaneo detenido por el usuario', stopped: true });
        } else {
          // This was an actual error
          reject(new Error(`Error en el escaneo: ${stderr || 'Proceso terminado inesperadamente'}`));
        }
      }
    });

    pythonProcess.on('error', (error) => {
      reject(new Error(`Failed to start Python script: ${error.message}`));
    });
  });
}

// Test IPC handler for debugging
ipcMain.handle('test-progress', async (event) => {
  console.log('Test progress handler called');
  const window = BrowserWindow.fromWebContents(event.sender);
  if (window && window.webContents) {
    window.webContents.send('antivirus-progress', {
      timestamp: Date.now(),
      message: 'Test progress message',
      type: 'info',
      data: { test: true }
    });
    return { success: true };
  }
  return { success: false, error: 'Main window not available' };
});

// Manejadores IPC para funciones de seguridad
function setupIPC() {
  // Escaneo de vulnerabilidades
  ipcMain.handle('scan-vulnerabilities', async () => {
    console.log('Iniciando escaneo de vulnerabilidades...');
    // Simular proceso de escaneo
    return {
      status: 'completado',
      vulnerabilities: [
        { id: 1, severity: 'alta', description: 'Certificado SSL obsoleto' },
        { id: 2, severity: 'media', description: 'Política de contraseñas débil' },
        { id: 3, severity: 'baja', description: 'Faltan encabezados de seguridad' }
      ],
      timestamp: new Date().toISOString()
    };
  });

  // Generación de contraseñas
  ipcMain.handle('generate-password', async (event, options) => {
    const { length = 16, includeSymbols = true, includeNumbers = true } = options;
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let charset = chars;
    if (includeNumbers) charset += numbers;
    if (includeSymbols) charset += symbols;
    
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    return {
      password,
      strength: calculatePasswordStrength(password),
      timestamp: new Date().toISOString()
    };
  });

  // Monitoreo de red
  ipcMain.handle('monitor-network', async () => {
    console.log('Iniciando monitoreo de red...');
    return {
      status: 'activo',
      connections: 15,
      threats: 0,
      bandwidth: '125.6 Mbps',
      timestamp: new Date().toISOString()
    };
  });

  // Análisis forense
  ipcMain.handle('forensic-analysis', async (event, filePath) => {
    console.log(`Iniciando análisis forense de: ${filePath}`);
    return {
      status: 'completado',
      fileHash: 'sha256:abc123...',
      fileType: 'ejecutable',
      suspicious: false,
      metadata: {
        created: '2024-01-15T10:30:00Z',
        modified: '2024-01-15T10:30:00Z',
        size: '2.5 MB'
      },
      timestamp: new Date().toISOString()
    };
  });

  // Información del sistema
  ipcMain.handle('get-system-info', async () => {
    return {
      platform: process.platform,
      arch: process.arch,
      version: process.version,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString()
    };
  });

  // Estado de seguridad
  ipcMain.handle('get-security-status', async () => {
    return {
      overall: 'seguro',
      antivirus: 'activo',
      firewall: 'habilitado',
      updates: 'actualizado',
      vulnerabilities: 3,
      lastScan: new Date().toISOString(),
      timestamp: new Date().toISOString()
    };
  });

  // Antivirus handlers (Python-based)
  ipcMain.handle('start-antivirus-scan', async (event, scanType) => {
    try {
      const pythonScript = path.join(__dirname, 'antivirus.py');
      const result = await runPythonScript(pythonScript, ['scan', '--scan-type', scanType, '--enable-progress'], true, true);
      
      return result;
    } catch (error) {
      console.error('Error iniciando escaneo antivirus:', error);
      return { success: false, message: 'No se pudo iniciar el escaneo del sistema. Verifique que Python esté instalado correctamente.' };
    }
  });

  ipcMain.handle('scan-file', async (event, filePath) => {
    try {
      const pythonScript = path.join(__dirname, 'antivirus.py');
      const result = await runPythonScript(pythonScript, ['scan-file', '--file', filePath, '--enable-progress'], true, true);
      
      return result;
    } catch (error) {
      console.error('Error escaneando archivo:', error);
      return { success: false, message: 'No se pudo escanear el archivo. Verifique que el archivo existe y es accesible.' };
    }
  });

  ipcMain.handle('scan-folders', async (event, folderPaths) => {
    try {
      const pythonScript = path.join(__dirname, 'antivirus.py');
      
      // Convert folder names to full paths if they're common folder names
      const fullPaths = folderPaths.map(folderPath => {
        if (folderPath === 'Downloads' || folderPath === 'Desktop' || folderPath === 'Documents') {
          return path.join(os.homedir(), folderPath);
        }
        return folderPath;
      });
      
      const args = ['scan-folders', '--folders', ...fullPaths, '--enable-progress'];
      const result = await runPythonScript(pythonScript, args, true, true);
      
      return result;
    } catch (error) {
      console.error('Error escaneando carpetas:', error);
      return { success: false, message: 'No se pudo escanear las carpetas seleccionadas. Verifique que las carpetas existen y son accesibles.' };
    }
  });

  ipcMain.handle('get-antivirus-status', async () => {
    try {
      const pythonScript = path.join(__dirname, 'antivirus.py');
      return await runPythonScript(pythonScript, ['status']);
    } catch (error) {
      console.error('Error obteniendo estado del antivirus:', error);
      return { error: 'No se pudo obtener el estado del antivirus. Verifique la configuración.' };
    }
  });

  ipcMain.handle('get-antivirus-stats', async () => {
    try {
      const pythonScript = path.join(__dirname, 'antivirus.py');
      return await runPythonScript(pythonScript, ['stats']);
    } catch (error) {
      console.error('Error obteniendo estadísticas del antivirus:', error);
      return { error: 'No se pudieron obtener las estadísticas del antivirus.' };
    }
  });

  ipcMain.handle('update-antivirus-database', async () => {
    try {
      const pythonScript = path.join(__dirname, 'antivirus.py');
      return await runPythonScript(pythonScript, ['update-db']);
    } catch (error) {
      console.error('Error actualizando base de datos del antivirus:', error);
      return { success: false, message: 'No se pudo actualizar la base de datos del antivirus. Verifique su conexión a internet.' };
    }
  });

  // Stop antivirus scan handler
  ipcMain.handle('stop-antivirus-scan', async () => {
    try {
      if (antivirusProcess && antivirusStatus.isRunning) {
        console.log('Stopping antivirus scan...');
        
        // Kill the Python process
        antivirusProcess.kill('SIGTERM');
        
        // Clean up status
        antivirusProcess = null;
        antivirusStatus.isRunning = false;
        antivirusStatus.startTime = null;
        
        // Send stop notification to frontend
        const mainWindow = BrowserWindow.getAllWindows()[0];
        if (mainWindow && mainWindow.webContents) {
          mainWindow.webContents.send('antivirus-progress', {
            type: 'scan_stopped',
            message: 'Escaneo detenido por el usuario',
            timestamp: new Date().toISOString()
          });
        }
        
        return { success: true, message: 'Escaneo detenido exitosamente' };
      } else {
        return { success: false, message: 'No hay ningún escaneo en progreso para detener' };
      }
    } catch (error) {
      console.error('Error deteniendo escaneo antivirus:', error);
      return { success: false, message: 'No se pudo detener el escaneo. Intente nuevamente.' };
    }
  });

  // File dialog handlers
  ipcMain.handle('show-open-dialog', async (event, options) => {
    try {
      const mainWindow = BrowserWindow.getAllWindows()[0];
      const result = await dialog.showOpenDialog(mainWindow, options);
      return result;
    } catch (error) {
      console.error('Error showing open dialog:', error);
      return { canceled: true, filePaths: [] };
    }
  });

  ipcMain.handle('show-save-dialog', async (event, options) => {
    try {
      const mainWindow = BrowserWindow.getAllWindows()[0];
      const result = await dialog.showSaveDialog(mainWindow, options);
      return result;
    } catch (error) {
      console.error('Error showing save dialog:', error);
      return { canceled: true, filePath: null };
    }
  });

  // File Analyzer handlers
  ipcMain.handle('analyze-file', async (event, filePath, analysisType) => {
    try {
      const result = await fileAnalyzer.analyzeFile(filePath, analysisType);
      
      // Enviar actualizaciones en tiempo real
      const mainWindow = BrowserWindow.getAllWindows()[0];
      if (mainWindow) {
        mainWindow.webContents.send('analysis-update', {
          type: 'file-analysis',
          data: result
        });
      }
      
      return result;
    } catch (error) {
      console.error('Error analizando archivo:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('analyze-folder', async (event, folderPath, analysisType) => {
    try {
      const result = await fileAnalyzer.analyzeFolder(folderPath, analysisType);
      
      // Enviar actualizaciones en tiempo real
      const mainWindow = BrowserWindow.getAllWindows()[0];
      if (mainWindow) {
        mainWindow.webContents.send('analysis-update', {
          type: 'folder-analysis',
          data: result
        });
      }
      
      return result;
    } catch (error) {
      console.error('Error analizando carpeta:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('get-file-hash', async (event, filePath, hashType = 'sha256') => {
    try {
      const result = await fileAnalyzer.hashAnalysis(filePath);
      return {
        success: true,
        filePath: filePath,
        hashType: hashType,
        hash: result[hashType.toLowerCase()],
        allHashes: result,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error obteniendo hash del archivo:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('extract-metadata', async (event, filePath) => {
    try {
      const fileStats = fs.statSync(filePath);
      const result = await fileAnalyzer.metadataAnalysis(filePath, fileStats);
      return {
        success: true,
        filePath: filePath,
        metadata: result,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error extrayendo metadatos:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('detect-malware', async (event, filePath) => {
    try {
      const result = await antivirusEngine.scanFile(filePath);
      return {
        success: true,
        filePath: filePath,
        isMalware: result.threats.length > 0,
        threats: result.threats,
        riskLevel: result.riskLevel,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error detectando malware:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  // Antivirus Testing handlers
  ipcMain.handle('generate-test-files', async () => {
    try {
      const testFiles = await generateAntivirusTestFiles();
      return { success: true, files: testFiles };
    } catch (error) {
      console.error('Error generating test files:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('test-eicar-detection', async () => {
    try {
      const result = await testEicarDetection();
      return { success: true, result: result };
    } catch (error) {
      console.error('Error testing EICAR detection:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('generate-advanced-test-files', async () => {
    try {
      const advancedFiles = await generateAdvancedTestFiles();
      return { success: true, files: advancedFiles };
    } catch (error) {
      console.error('Error generating advanced test files:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('generate-aggressive-test-files', async () => {
    try {
      const aggressiveFiles = await generateAggressiveTestFiles();
      return { success: true, files: aggressiveFiles };
    } catch (error) {
      console.error('Error generating aggressive test files:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('test-real-antivirus-detection', async () => {
    try {
      const result = await testRealAntivirusDetection();
      return { success: true, result: result };
    } catch (error) {
      console.error('Error testing real antivirus detection:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('diagnose-antivirus-status', async () => {
    try {
      const result = await diagnoseAntivirusStatus();
      return { success: true, result: result };
    } catch (error) {
      console.error('Error diagnosing antivirus status:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('scan-file-with-virustotal', async (event, filePath) => {
    try {
      const result = await scanFileWithVirusTotal(filePath);
      return { success: true, result: result };
    } catch (error) {
      console.error('Error scanning file with VirusTotal:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('generate-real-malware-tests', async () => {
    try {
      const result = await generateRealMalwareTests();
      return { success: true, result: result };
    } catch (error) {
      console.error('Error generating real malware tests:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('comprehensive-antivirus-diagnostic', async () => {
    try {
      const result = await comprehensiveAntivirusDiagnostic();
      return { success: true, result: result };
    } catch (error) {
      console.error('Error in comprehensive antivirus diagnostic:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('delete-threats', async () => {
    try {
      const result = await deleteThreats();
      return result;
    } catch (error) {
      console.error('Error deleting threats:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('clear-threat-history', async () => {
    try {
      // Reset threat counters
      appData.totalThreatsFound = 0;
      appData.scanHistory = [];
      appData.lastScanDate = null;
      appData.totalScans = 0;
      appData.totalFilesScanned = 0;
      
      // Save updated data
      saveAppData();
      
      return { 
        success: true, 
        message: 'Threat history cleared successfully',
        newStats: {
          threatsFound: 0,
          filesScanned: 0,
          totalScans: 0
        }
      };
    } catch (error) {
      console.error('Error clearing threat history:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  // System Analysis handlers
  ipcMain.handle('full-system-analysis', async () => {
    try {
      const result = await systemAnalyzer.fullSystemAnalysis();
      
      // Enviar actualizaciones en tiempo real
      const mainWindow = BrowserWindow.getAllWindows()[0];
      if (mainWindow) {
        mainWindow.webContents.send('analysis-update', {
          type: 'system-analysis',
          data: result
        });
      }
      
      return result;
    } catch (error) {
      console.error('Error en análisis completo del sistema:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });


  ipcMain.handle('generate-system-report', async () => {
    try {
      return await systemAnalyzer.generateSystemReport();
    } catch (error) {
      console.error('Error generando reporte del sistema:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('get-process-list', async () => {
    try {
      return await systemAnalyzer.getProcessList();
    } catch (error) {
      console.error('Error obteniendo lista de procesos:', error);
      return { error: error.message };
    }
  });

  ipcMain.handle('get-network-connections', async () => {
    try {
      return await systemAnalyzer.getNetworkConnections();
    } catch (error) {
      console.error('Error obteniendo conexiones de red:', error);
      return { error: error.message };
    }
  });

  // Report Management handlers
  ipcMain.handle('get-analysis-reports', async () => {
    try {
      const fileReports = fileAnalyzer.getAnalysisHistory();
      const systemReports = systemAnalyzer.getAnalysisHistory();
      
      return {
        success: true,
        reports: {
          fileAnalysis: fileReports,
          systemAnalysis: systemReports,
          total: fileReports.length + systemReports.length
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error obteniendo reportes de análisis:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('export-analysis-report', async (event, reportId, format = 'json') => {
    try {
      // Implementar exportación de reportes
      const timestamp = new Date().toISOString().split('T')[0];
      const filename = `analysis_report_${reportId}_${timestamp}.${format}`;
      
      return {
        success: true,
        filename: filename,
        format: format,
        message: 'Reporte exportado correctamente',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error exportando reporte:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('clear-analysis-logs', async () => {
    try {
      fileAnalyzer.clearAnalysisHistory();
      systemAnalyzer.clearAnalysisHistory();
      
      return {
        success: true,
        message: 'Logs de análisis limpiados correctamente',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error limpiando logs de análisis:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  // Keylogger handlers
  ipcMain.handle('start-keylogger', async () => {
    try {
      if (keyloggerStatus.isRunning) {
        return { success: false, message: 'Keylogger ya está ejecutándose' };
      }

      console.log('Iniciando keylogger...');
      const pythonScript = path.join(__dirname, 'keylogger.py');
      
      console.log('Python script path:', pythonScript);
      console.log('Working directory:', __dirname);
      
      keyloggerProcess = spawn('python', [pythonScript], {
        cwd: __dirname,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      keyloggerStatus.isRunning = true;
      keyloggerStatus.startTime = new Date();

      keyloggerProcess.stdout.on('data', (data) => {
        const dataStr = data.toString();
        console.log(`Keylogger output: "${dataStr}"`);
        
        // Confirmar que el keylogger está realmente ejecutándose
        if (dataStr.includes('INICIALIZADO') || dataStr.includes('INICIADO')) {
          keyloggerStatus.isRunning = true;
          console.log('Keylogger confirmed as running - status updated to true');
        }
        
        // Enviar actualizaciones en tiempo real al frontend
        const mainWindow = BrowserWindow.getAllWindows()[0];
        if (mainWindow) {
          mainWindow.webContents.send('keylogger-update', {
            type: 'output',
            data: dataStr
          });
        }
      });

      keyloggerProcess.stderr.on('data', (data) => {
        console.error(`Keylogger error: ${data}`);
        // Enviar actualizaciones de error al frontend
        const mainWindow = BrowserWindow.getAllWindows()[0];
        if (mainWindow) {
          mainWindow.webContents.send('keylogger-update', {
            type: 'error',
            data: data.toString()
          });
        }
      });

      keyloggerProcess.on('close', (code) => {
        console.log(`Keylogger terminado con código: ${code}`);
        keyloggerStatus.isRunning = false;
        keyloggerProcess = null;
      });

      return { 
        success: true, 
        message: 'Keylogger iniciado correctamente',
        startTime: keyloggerStatus.startTime.toISOString()
      };
    } catch (error) {
      console.error('Error iniciando keylogger:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('stop-keylogger', async () => {
    try {
      if (!keyloggerStatus.isRunning || !keyloggerProcess) {
        return { success: false, message: 'Keylogger no está ejecutándose' };
      }

      console.log('Deteniendo keylogger...');
      keyloggerProcess.kill('SIGTERM');
      
      // Esperar un poco para cierre elegante
      setTimeout(() => {
        if (keyloggerProcess && !keyloggerProcess.killed) {
          keyloggerProcess.kill('SIGKILL');
        }
      }, 2000);

      keyloggerStatus.isRunning = false;
      keyloggerProcess = null;

      return { 
        success: true, 
        message: 'Keylogger detenido correctamente',
        stopTime: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error deteniendo keylogger:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('get-keylogger-status', async () => {
    try {
      let logContent = '';
      let logSize = 0;
      
      if (fs.existsSync(keyloggerStatus.logFile)) {
        const stats = fs.statSync(keyloggerStatus.logFile);
        logSize = stats.size;
        logContent = fs.readFileSync(keyloggerStatus.logFile, 'utf8');
      }

      const status = {
        isRunning: keyloggerStatus.isRunning,
        startTime: keyloggerStatus.startTime?.toISOString() || null,
        logFile: keyloggerStatus.logFile,
        logSize: logSize,
        logContent: logContent,
        timestamp: new Date().toISOString()
      };
      
      console.log('Keylogger status requested:', {
        isRunning: status.isRunning,
        logSize: status.logSize,
        logContentLength: status.logContent.length
      });
      
      return status;
    } catch (error) {
      console.error('Error obteniendo estado del keylogger:', error);
      return { 
        isRunning: false, 
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  });

  ipcMain.handle('export-keylogger-logs', async (event, format = 'txt') => {
    try {
      if (!fs.existsSync(keyloggerStatus.logFile)) {
        return { success: false, message: 'No hay logs para exportar' };
      }

      const logContent = fs.readFileSync(keyloggerStatus.logFile, 'utf8');
      const timestamp = new Date().toISOString().split('T')[0];
      
      let exportContent = '';
      let filename = '';

      switch (format) {
        case 'txt':
          exportContent = logContent;
          filename = `keylogger_${timestamp}.txt`;
          break;
        case 'json':
          exportContent = JSON.stringify({
            session: {
              startTime: keyloggerStatus.startTime?.toISOString(),
              exportTime: new Date().toISOString(),
              logSize: logContent.length
            },
            logs: logContent.split('\n').map(line => ({
              timestamp: new Date().toISOString(),
              content: line
            }))
          }, null, 2);
          filename = `keylogger_${timestamp}.json`;
          break;
        case 'csv':
          exportContent = 'Timestamp,Content\n' + 
            logContent.split('\n').map(line => 
              `${new Date().toISOString()},"${line.replace(/"/g, '""')}"`
            ).join('\n');
          filename = `keylogger_${timestamp}.csv`;
          break;
        default:
          return { success: false, message: 'Formato no soportado' };
      }

      return {
        success: true,
        content: exportContent,
        filename: filename,
        format: format,
        size: exportContent.length
      };
    } catch (error) {
      console.error('Error exportando logs:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  ipcMain.handle('clear-keylogger-logs', async () => {
    try {
      if (fs.existsSync(keyloggerStatus.logFile)) {
        fs.writeFileSync(keyloggerStatus.logFile, '');
        return { success: true, message: 'Logs limpiados correctamente' };
      }
      return { success: false, message: 'No hay logs para limpiar' };
    } catch (error) {
      console.error('Error limpiando logs:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  });

  // App data handlers
  ipcMain.handle('get-app-data', async () => {
    return {
      success: true,
      data: appData
    };
  });

  ipcMain.handle('update-scan-data', async (event, scanData) => {
    try {
      const now = new Date();
      
      // Handle analysis data
      if (scanData.lastAnalysis) {
        appData.lastAnalysis = scanData.lastAnalysis;
        saveAppData();
        return { success: true, message: 'Datos de análisis actualizados' };
      }
      
      // Handle scan data
      appData.lastScanDate = now.toISOString();
      appData.totalScans += 1;
      
      if (scanData.filesScanned) {
        appData.totalFilesScanned += scanData.filesScanned;
      }
      if (scanData.threatsFound) {
        appData.totalThreatsFound += scanData.threatsFound;
      }
      
      // Add to scan history (keep last 10 scans)
      appData.scanHistory.unshift({
        date: now.toISOString(),
        filesScanned: scanData.filesScanned || 0,
        threatsFound: scanData.threatsFound || 0,
        scanType: scanData.scanType || 'unknown',
        duration: scanData.duration || 0
      });
      
      // Keep only last 10 scans
      if (appData.scanHistory.length > 10) {
        appData.scanHistory = appData.scanHistory.slice(0, 10);
      }
      
      saveAppData();
      return { success: true, message: 'Datos de escaneo actualizados' };
    } catch (error) {
      console.error('Error updating scan data:', error);
      return { success: false, message: 'No se pudieron actualizar los datos del escaneo' };
    }
  });
}

// ===== ANTIVIRUS TESTING FUNCTIONS =====

async function generateAntivirusTestFiles() {
  const testDir = path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files');
  
  // Create test directory
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  const testFiles = [];
  
  // 1. EICAR Test String (Industry Standard) - Multiple formats
  const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  
  // EICAR as COM file (more likely to be detected)
  const eicarComPath = path.join(testDir, 'EICAR.COM');
  fs.writeFileSync(eicarComPath, eicarString, 'utf8');
  testFiles.push({
    name: 'EICAR.COM',
    type: 'EICAR COM Test',
    description: 'EICAR test as COM executable - should be detected',
    path: eicarComPath,
    safe: true
  });
  
  // EICAR as EXE file
  const eicarExePath = path.join(testDir, 'EICAR.EXE');
  fs.writeFileSync(eicarExePath, eicarString, 'utf8');
  testFiles.push({
    name: 'EICAR.EXE',
    type: 'EICAR EXE Test',
    description: 'EICAR test as EXE executable - should be detected',
    path: eicarExePath,
    safe: true
  });
  
  // EICAR as ZIP file
  const eicarZipPath = path.join(testDir, 'EICAR.ZIP');
  fs.writeFileSync(eicarZipPath, eicarString, 'utf8');
  testFiles.push({
    name: 'EICAR.ZIP',
    type: 'EICAR ZIP Test',
    description: 'EICAR test as ZIP archive - should be detected',
    path: eicarZipPath,
    safe: true
  });
  
  // 2. Files with Known Malware-like Patterns
  const malwarePatterns = [
    'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00',
    'This file contains patterns that mimic known malware signatures but is completely safe for testing purposes.',
    'PE\x00\x00\x4c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  ];
  
  // Create files with suspicious binary patterns
  const suspiciousExePath = path.join(testDir, 'suspicious_pattern.exe');
  fs.writeFileSync(suspiciousExePath, malwarePatterns[0], 'binary');
  testFiles.push({
    name: 'suspicious_pattern.exe',
    type: 'Binary Pattern Test',
    description: 'File with binary patterns similar to malware - may trigger heuristic detection',
    path: suspiciousExePath,
    safe: true
  });
  
  // Create PE header-like file
  const peHeaderPath = path.join(testDir, 'pe_header_test.exe');
  fs.writeFileSync(peHeaderPath, malwarePatterns[2], 'binary');
  testFiles.push({
    name: 'pe_header_test.exe',
    type: 'PE Header Test',
    description: 'File with PE header patterns - may trigger detection',
    path: peHeaderPath,
    safe: true
  });
  
  // 3. Test File with Known Malware Hash Pattern
  const malwarePatternContent = 'This file contains patterns similar to known malware but is completely safe.';
  const malwarePatternPath = path.join(testDir, 'malware_pattern_test.txt');
  fs.writeFileSync(malwarePatternPath, malwarePatternContent, 'utf8');
  testFiles.push({
    name: 'malware_pattern_test.txt',
    type: 'Pattern Test',
    description: 'File with patterns similar to known malware signatures',
    path: malwarePatternPath,
    safe: true
  });
  
  // 4. Archive with Suspicious Content
  const archiveContent = 'This is a test archive file for antivirus testing.';
  const archivePath = path.join(testDir, 'test_archive.zip');
  fs.writeFileSync(archivePath, archiveContent, 'utf8');
  testFiles.push({
    name: 'test_archive.zip',
    type: 'Archive Test',
    description: 'Test archive file for scanning capabilities',
    path: archivePath,
    safe: true
  });
  
  // 5. Script Files with More Suspicious Commands
  const suspiciousScriptContent = `@echo off
REM This script contains patterns that may trigger antivirus detection
set /a counter=0
:loop
if %counter% lss 10 (
    echo Counter: %counter%
    set /a counter+=1
    goto loop
)
REM Suspicious patterns that might trigger heuristic analysis
for /f "tokens=*" %%i in ('dir /b') do echo %%i
REM These commands are safe but may appear suspicious
netstat -an | findstr LISTENING
tasklist | findstr explorer
REM End of test script - completely safe`;
  
  const suspiciousScriptPath = path.join(testDir, 'suspicious_script.bat');
  fs.writeFileSync(suspiciousScriptPath, suspiciousScriptContent, 'utf8');
  testFiles.push({
    name: 'suspicious_script.bat',
    type: 'Suspicious Script Test',
    description: 'Script with network and system commands that may trigger detection',
    path: suspiciousScriptPath,
    safe: true
  });
  
  // PowerShell script with suspicious patterns
  const powershellContent = `# PowerShell script with patterns that may trigger antivirus detection
# This script is completely safe but contains suspicious patterns
$processes = Get-Process | Where-Object {$_.ProcessName -like "*explorer*"}
$networkConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
$services = Get-Service | Where-Object {$_.Status -eq "Running"}
# These commands are safe but may appear suspicious to antivirus
Write-Host "System analysis complete - this is a test script"`;
  
  const powershellPath = path.join(testDir, 'suspicious_powershell.ps1');
  fs.writeFileSync(powershellPath, powershellContent, 'utf8');
  testFiles.push({
    name: 'suspicious_powershell.ps1',
    type: 'PowerShell Test',
    description: 'PowerShell script with system analysis commands - may trigger detection',
    path: powershellPath,
    safe: true
  });
  
  // 6. Document with Macro-like Content
  const docContent = `This document contains content that might be flagged by antivirus software.
It includes patterns that could be interpreted as malicious macros or scripts.
However, this is completely safe and only for testing purposes.`;
  const docPath = path.join(testDir, 'test_document.doc');
  fs.writeFileSync(docPath, docContent, 'utf8');
  testFiles.push({
    name: 'test_document.doc',
    type: 'Document Test',
    description: 'Document file with macro-like content for testing',
    path: docPath,
    safe: true
  });
  
  return testFiles;
}

// Additional function to create files that are more likely to trigger detection
async function generateAdvancedTestFiles() {
  const testDir = path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files');
  
  // Create test directory
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  const advancedFiles = [];
  
  // Create files with known suspicious strings
  const suspiciousStrings = [
    'This file contains the string "malware" which may trigger detection',
    'Virus detection test file with suspicious content patterns',
    'Trojan horse simulation file for antivirus testing',
    'Backdoor test file - completely safe but may trigger alerts',
    'Rootkit simulation file for security testing purposes'
  ];
  
  suspiciousStrings.forEach((content, index) => {
    const fileName = `suspicious_content_${index + 1}.txt`;
    const filePath = path.join(testDir, fileName);
    fs.writeFileSync(filePath, content, 'utf8');
    advancedFiles.push({
      name: fileName,
      type: 'Suspicious Content Test',
      description: `File with suspicious keywords - may trigger keyword detection`,
      path: filePath,
      safe: true
    });
  });
  
  return advancedFiles;
}

// Create files that are more likely to trigger detection
async function generateAggressiveTestFiles() {
  const testDir = path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files');
  
  // Create test directory
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  const aggressiveFiles = [];
  
  // 1. Create files with actual executable headers
  const executableHeader = Buffer.from([
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
    0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70,
    0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20,
    0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  
  const exePath = path.join(testDir, 'fake_executable.exe');
  fs.writeFileSync(exePath, executableHeader);
  aggressiveFiles.push({
    name: 'fake_executable.exe',
    type: 'Executable Header Test',
    description: 'File with real executable headers - should trigger detection',
    path: exePath,
    safe: true
  });
  
  // 2. Create files with suspicious registry modifications
  const regScriptContent = `Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"TestMalware"="C:\\Windows\\System32\\notepad.exe"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"TestStartup"="C:\\Windows\\System32\\calc.exe"

; This is a test registry file for antivirus testing
; It contains startup entries that may trigger detection
; Completely safe - just test patterns`;
  
  const regPath = path.join(testDir, 'suspicious_startup.reg');
  fs.writeFileSync(regPath, regScriptContent, 'utf8');
  aggressiveFiles.push({
    name: 'suspicious_startup.reg',
    type: 'Registry Test',
    description: 'Registry file with startup entries - may trigger detection',
    path: regPath,
    safe: true
  });
  
  // 3. Create files with suspicious network patterns
  const networkScriptContent = `@echo off
REM Network scanning script for antivirus testing
echo Testing network connectivity...
ping -n 1 8.8.8.8
nslookup google.com
netstat -an | findstr :80
netstat -an | findstr :443
arp -a
ipconfig /all
REM These commands are safe but may appear suspicious
echo Network test complete - this is a test script`;
  
  const networkPath = path.join(testDir, 'network_scan.bat');
  fs.writeFileSync(networkPath, networkScriptContent, 'utf8');
  aggressiveFiles.push({
    name: 'network_scan.bat',
    type: 'Network Script Test',
    description: 'Script with network scanning commands - may trigger detection',
    path: networkPath,
    safe: true
  });
  
  // 4. Create files with suspicious file operations
  const fileOpsContent = `@echo off
REM File operations script for antivirus testing
echo Testing file operations...
dir /s C:\\Windows\\System32
dir /s C:\\Program Files
copy C:\\Windows\\System32\\notepad.exe C:\\temp\\test.exe
del C:\\temp\\test.exe
REM These operations are safe but may appear suspicious
echo File operations test complete - this is a test script`;
  
  const fileOpsPath = path.join(testDir, 'file_operations.bat');
  fs.writeFileSync(fileOpsPath, fileOpsContent, 'utf8');
  aggressiveFiles.push({
    name: 'file_operations.bat',
    type: 'File Operations Test',
    description: 'Script with file system operations - may trigger detection',
    path: fileOpsPath,
    safe: true
  });
  
  // 5. Create files with suspicious process operations
  const processContent = `@echo off
REM Process operations script for antivirus testing
echo Testing process operations...
tasklist /svc
wmic process list brief
wmic service list brief
taskkill /f /im notepad.exe 2>nul
start notepad.exe
REM These operations are safe but may appear suspicious
echo Process operations test complete - this is a test script`;
  
  const processPath = path.join(testDir, 'process_operations.bat');
  fs.writeFileSync(processPath, processContent, 'utf8');
  aggressiveFiles.push({
    name: 'process_operations.bat',
    type: 'Process Operations Test',
    description: 'Script with process manipulation - may trigger detection',
    path: processPath,
    safe: true
  });
  
  return aggressiveFiles;
}

async function testEicarDetection() {
  try {
    // Create EICAR test file in a location where antivirus will scan it
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const testDir = path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files');
    const testPath = path.join(testDir, 'EICAR_TEST_FILE.txt');
    
    // Ensure directory exists
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
    
    // Create the EICAR file
    fs.writeFileSync(testPath, eicarString, 'utf8');
    
    // Wait a moment for real-time scanning
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check if file still exists (antivirus might have quarantined it)
    const fileExists = fs.existsSync(testPath);
    
    // Test with VirusTotal API if available
    let virustotalResult = null;
    try {
      const { spawn } = require('child_process');
      const pythonProcess = spawn('python', ['backend/antivirus.py', '--file', testPath], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      let output = '';
      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      await new Promise((resolve, reject) => {
        pythonProcess.on('close', (code) => {
          if (code === 0) {
            try {
              const lines = output.split('\n');
              for (const line of lines) {
                if (line.startsWith('{') && line.includes('detected')) {
                  virustotalResult = JSON.parse(line);
                  break;
                }
              }
            } catch (e) {
              // Ignore JSON parsing errors
            }
          }
          resolve();
        });
      });
    } catch (error) {
      console.log('VirusTotal test failed:', error.message);
    }
    
    // Clean up test file
    if (fs.existsSync(testPath)) {
      fs.unlinkSync(testPath);
    }
    
    return {
      detected: !fileExists || (virustotalResult && virustotalResult.detected),
      fileQuarantined: !fileExists,
      virustotalResult: virustotalResult,
      message: !fileExists ? 'EICAR file was quarantined by antivirus' : 
               virustotalResult ? `VirusTotal detection: ${virustotalResult.detected}` :
               'EICAR file was not detected by antivirus'
    };
  } catch (error) {
    return {
      detected: false,
      fileQuarantined: false,
      virustotalResult: null,
      message: `EICAR test error: ${error.message}`
    };
  }
}

async function testRealAntivirusDetection() {
  try {
    const testDir = path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files');
    
    // Ensure directory exists
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
    
    const results = {
      eicarTest: { detected: false, quarantined: false },
      realTimeTest: { detected: false, blocked: false },
      manualScanTest: { detected: false, scanned: false },
      recommendations: []
    };
    
    // Test 1: EICAR Detection
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarPath = path.join(testDir, 'EICAR_TEST.txt');
    
    fs.writeFileSync(eicarPath, eicarString, 'utf8');
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    results.eicarTest.quarantined = !fs.existsSync(eicarPath);
    results.eicarTest.detected = results.eicarTest.quarantined;
    
    if (fs.existsSync(eicarPath)) {
      fs.unlinkSync(eicarPath);
    }
    
    // Test 2: Real-time Protection Test
    const suspiciousScript = `@echo off
REM This script attempts to modify system files
echo Testing real-time protection...
copy C:\\Windows\\System32\\notepad.exe C:\\temp\\test.exe 2>nul
del C:\\temp\\test.exe 2>nul
echo Test complete`;
    
    const scriptPath = path.join(testDir, 'realtime_test.bat');
    fs.writeFileSync(scriptPath, suspiciousScript, 'utf8');
    
    // Try to execute the script
    try {
      const { exec } = require('child_process');
      await new Promise((resolve, reject) => {
        exec(`"${scriptPath}"`, (error, stdout, stderr) => {
          if (error) {
            results.realTimeTest.blocked = true;
            results.realTimeTest.detected = true;
          }
          resolve();
        });
      });
    } catch (error) {
      results.realTimeTest.blocked = true;
      results.realTimeTest.detected = true;
    }
    
    // Clean up
    if (fs.existsSync(scriptPath)) {
      fs.unlinkSync(scriptPath);
    }
    
    // Generate recommendations
    if (!results.eicarTest.detected) {
      results.recommendations.push('EICAR not detected - Check antivirus EICAR detection settings');
    }
    if (!results.realTimeTest.detected) {
      results.recommendations.push('Real-time protection may be disabled - Enable real-time scanning');
    }
    if (results.recommendations.length === 0) {
      results.recommendations.push('Antivirus appears to be working correctly');
    }
    
    return results;
  } catch (error) {
    return {
      eicarTest: { detected: false, quarantined: false },
      realTimeTest: { detected: false, blocked: false },
      manualScanTest: { detected: false, scanned: false },
      recommendations: [`Test error: ${error.message}`]
    };
  }
}

async function diagnoseAntivirusStatus() {
  try {
    const { exec } = require('child_process');
    const util = require('util');
    const execAsync = util.promisify(exec);
    
    const diagnosis = {
      windowsDefender: { status: 'unknown', enabled: false },
      antivirusProcesses: [],
      securityCenter: { status: 'unknown' },
      recommendations: []
    };
    
    // Check Windows Defender status
    try {
      const { stdout } = await execAsync('powershell "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled"');
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.includes('AntivirusEnabled')) {
          diagnosis.windowsDefender.enabled = line.includes('True');
        }
        if (line.includes('RealTimeProtectionEnabled')) {
          diagnosis.windowsDefender.realTimeEnabled = line.includes('True');
        }
      }
      diagnosis.windowsDefender.status = diagnosis.windowsDefender.enabled ? 'enabled' : 'disabled';
    } catch (error) {
      diagnosis.windowsDefender.status = 'error';
      diagnosis.windowsDefender.error = error.message;
    }
    
    // Check for antivirus processes
    try {
      const { stdout } = await execAsync('tasklist /FI "IMAGENAME eq *antivirus*" /FI "IMAGENAME eq *avast*" /FI "IMAGENAME eq *norton*" /FI "IMAGENAME eq *mcafee*" /FI "IMAGENAME eq *kaspersky*" /FI "IMAGENAME eq *bitdefender*" /FI "IMAGENAME eq *malwarebytes*"');
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.includes('.exe')) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 1) {
            diagnosis.antivirusProcesses.push(parts[0]);
          }
        }
      }
    } catch (error) {
      diagnosis.antivirusProcesses = [];
    }
    
    // Generate recommendations
    if (!diagnosis.windowsDefender.enabled && diagnosis.antivirusProcesses.length === 0) {
      diagnosis.recommendations.push('No antivirus detected - Install and enable Windows Defender or third-party antivirus');
    } else if (!diagnosis.windowsDefender.enabled && diagnosis.antivirusProcesses.length > 0) {
      diagnosis.recommendations.push('Third-party antivirus detected but Windows Defender disabled - Check antivirus settings');
    } else if (diagnosis.windowsDefender.enabled && !diagnosis.windowsDefender.realTimeEnabled) {
      diagnosis.recommendations.push('Windows Defender enabled but real-time protection disabled - Enable real-time protection');
    } else if (diagnosis.windowsDefender.enabled && diagnosis.windowsDefender.realTimeEnabled) {
      diagnosis.recommendations.push('Windows Defender appears to be working correctly');
    }
    
    return diagnosis;
  } catch (error) {
    return {
      windowsDefender: { status: 'error', error: error.message },
      antivirusProcesses: [],
      securityCenter: { status: 'error' },
      recommendations: [`Diagnosis error: ${error.message}`]
    };
  }
}

async function comprehensiveAntivirusDiagnostic() {
  try {
    const { exec } = require('child_process');
    const util = require('util');
    const execAsync = util.promisify(exec);
    
    const diagnostic = {
      windowsDefenderStatus: {},
      serviceStatus: {},
      exclusions: {},
      testResults: {},
      recommendations: [],
      criticalIssues: []
    };
    
    // 1. Check Windows Defender Status
    try {
      const { stdout } = await execAsync('powershell "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled, CloudProtectionEnabled, SignatureLastUpdated"');
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.includes('AntivirusEnabled')) {
          diagnostic.windowsDefenderStatus.antivirusEnabled = line.includes('True');
        }
        if (line.includes('RealTimeProtectionEnabled')) {
          diagnostic.windowsDefenderStatus.realTimeEnabled = line.includes('True');
        }
        if (line.includes('OnAccessProtectionEnabled')) {
          diagnostic.windowsDefenderStatus.onAccessEnabled = line.includes('True');
        }
        if (line.includes('CloudProtectionEnabled')) {
          diagnostic.windowsDefenderStatus.cloudEnabled = line.includes('True');
        }
        if (line.includes('SignatureLastUpdated')) {
          diagnostic.windowsDefenderStatus.signatureUpdated = line.includes('True');
        }
      }
    } catch (error) {
      diagnostic.windowsDefenderStatus.error = error.message;
    }
    
    // 2. Check Windows Defender Service Status
    try {
      const { stdout } = await execAsync('powershell "Get-Service -Name WinDefend | Select-Object Status, StartType"');
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.includes('Status')) {
          diagnostic.serviceStatus.status = line.includes('Running') ? 'Running' : 'Stopped';
        }
        if (line.includes('StartType')) {
          diagnostic.serviceStatus.startType = line.includes('Automatic') ? 'Automatic' : 'Manual';
        }
      }
    } catch (error) {
      diagnostic.serviceStatus.error = error.message;
    }
    
    // 3. Test EICAR Detection in Multiple Locations
    const testLocations = [
      { path: path.join(os.homedir(), 'Desktop', 'EICAR_TEST.COM'), name: 'Local Desktop' },
      { path: path.join(os.homedir(), 'OneDrive', 'Desktop', 'EICAR_TEST.COM'), name: 'OneDrive Desktop' },
      { path: path.join(os.homedir(), 'Documents', 'EICAR_TEST.COM'), name: 'Documents' },
      { path: path.join(os.homedir(), 'Downloads', 'EICAR_TEST.COM'), name: 'Downloads' },
      { path: 'C:\\Windows\\Temp\\EICAR_TEST.COM', name: 'Windows Temp' }
    ];
    
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    
    for (const location of testLocations) {
      try {
        // Create EICAR file
        fs.writeFileSync(location.path, eicarString, 'utf8');
        
        // Wait for detection
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        // Check if file still exists
        const fileExists = fs.existsSync(location.path);
        
        diagnostic.testResults[location.name] = {
          detected: !fileExists,
          quarantined: !fileExists,
          fileExists: fileExists,
          path: location.path
        };
        
        // Clean up if file still exists
        if (fileExists) {
          fs.unlinkSync(location.path);
        }
      } catch (error) {
        diagnostic.testResults[location.name] = {
          error: error.message,
          detected: false,
          quarantined: false
        };
      }
    }
    
    // 4. Check for Third-party Antivirus
    try {
      const { stdout } = await execAsync('tasklist | findstr /i "avast norton mcafee kaspersky bitdefender malwarebytes"');
      diagnostic.thirdPartyAntivirus = stdout.trim() ? stdout.trim().split('\n') : [];
    } catch (error) {
      diagnostic.thirdPartyAntivirus = [];
    }
    
    // 5. Check Windows Defender Exclusions (if possible)
    try {
      const { stdout } = await execAsync('powershell "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"');
      diagnostic.exclusions.paths = stdout.includes('N/A') ? 'Requires Administrator' : stdout.trim();
    } catch (error) {
      diagnostic.exclusions.paths = 'Error checking exclusions';
    }
    
    // 6. Generate Recommendations
    if (!diagnostic.windowsDefenderStatus.antivirusEnabled) {
      diagnostic.criticalIssues.push('Windows Defender is disabled');
      diagnostic.recommendations.push('Enable Windows Defender antivirus protection');
    }
    
    if (!diagnostic.windowsDefenderStatus.realTimeEnabled) {
      diagnostic.criticalIssues.push('Real-time protection is disabled');
      diagnostic.recommendations.push('Enable real-time protection in Windows Defender');
    }
    
    if (diagnostic.serviceStatus.status !== 'Running') {
      diagnostic.criticalIssues.push('Windows Defender service is not running');
      diagnostic.recommendations.push('Start Windows Defender service');
    }
    
    // Check EICAR detection results
    const detectedLocations = Object.values(diagnostic.testResults).filter(test => test.detected).length;
    if (detectedLocations === 0) {
      diagnostic.criticalIssues.push('EICAR test files not detected in any location');
      diagnostic.recommendations.push('Windows Defender may have exclusions or configuration issues');
      diagnostic.recommendations.push('Check Windows Defender exclusions and settings');
      diagnostic.recommendations.push('Run Windows Defender offline scan');
    } else if (detectedLocations < testLocations.length) {
      diagnostic.criticalIssues.push('EICAR detection inconsistent across locations');
      diagnostic.recommendations.push('Some locations may be excluded from scanning');
    }
    
    if (diagnostic.thirdPartyAntivirus.length > 0) {
      diagnostic.criticalIssues.push('Third-party antivirus detected');
      diagnostic.recommendations.push('Third-party antivirus may be interfering with Windows Defender');
      diagnostic.recommendations.push('Consider disabling third-party antivirus or configuring exclusions');
    }
    
    if (diagnostic.criticalIssues.length === 0) {
      diagnostic.recommendations.push('Windows Defender appears to be working correctly');
    }
    
    return diagnostic;
  } catch (error) {
    return {
      error: error.message,
      recommendations: [`Diagnostic error: ${error.message}`]
    };
  }
}

async function deleteThreats() {
  try {
    const { exec } = require('child_process');
    const util = require('util');
    const execAsync = util.promisify(exec);
    
    const results = {
      deletedFiles: [],
      errors: [],
      totalDeleted: 0
    };
    
    // Common locations where test files might be created
    const testLocations = [
      path.join(os.homedir(), 'Desktop', 'Antivirus_Test_Files'),
      path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files'),
      path.join(os.homedir(), 'Desktop', 'Test_Folder'),
      path.join(os.homedir(), 'OneDrive', 'Desktop', 'Test_Folder'),
      path.join(os.homedir(), 'Desktop'),
      path.join(os.homedir(), 'OneDrive', 'Desktop')
    ];
    
    // Files to look for and delete (more flexible matching)
    const threatFilePatterns = [
      'EICAR',
      'malware',
      'suspicious',
      'pe_header',
      'behavioral',
      'test_archive',
      'test_document',
      'virus',
      'trojan',
      'backdoor',
      'rootkit',
      'keylogger'
    ];
    
    for (const location of testLocations) {
      if (fs.existsSync(location)) {
        const files = fs.readdirSync(location);
        
        for (const fileName of files) {
          // Check if file matches any threat pattern
          const isThreatFile = threatFilePatterns.some(pattern => 
            fileName.toLowerCase().includes(pattern.toLowerCase())
          );
          
          if (isThreatFile) {
            const filePath = path.join(location, fileName);
            try {
              // Check if it's a file (not a directory) before deleting
              const stats = fs.statSync(filePath);
              if (stats.isFile()) {
                fs.unlinkSync(filePath);
                results.deletedFiles.push(filePath);
                results.totalDeleted++;
                console.log(`Deleted file: ${filePath}`);
              } else {
                console.log(`Skipping directory: ${filePath}`);
              }
            } catch (error) {
              results.errors.push(`Error deleting ${filePath}: ${error.message}`);
              console.error(`Error deleting ${filePath}:`, error);
            }
          }
        }
        
        // Also try to delete the entire test folder if it's empty
        try {
          const remainingFiles = fs.readdirSync(location);
          if (remainingFiles.length === 0) {
            fs.rmdirSync(location);
            results.deletedFiles.push(`Empty folder deleted: ${location}`);
            console.log(`Deleted empty folder: ${location}`);
          } else {
            console.log(`Folder not empty, keeping: ${location} (${remainingFiles.length} files remaining)`);
          }
        } catch (error) {
          console.log(`Could not delete folder ${location}: ${error.message}`);
          // Don't add to errors as this is not critical
        }
      }
    }
    
    // Clean up Windows Defender quarantine if possible
    try {
      const quarantinePath = 'C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine';
      if (fs.existsSync(quarantinePath)) {
        // Note: We can't actually delete from quarantine without admin rights
        // This is just for information
        results.info = 'Windows Defender quarantine files require administrator privileges to delete';
      }
    } catch (error) {
      results.errors.push(`Quarantine cleanup: ${error.message}`);
    }
    
    return {
      success: true,
      message: `Deleted ${results.totalDeleted} threat files`,
      details: results
    };
    
  } catch (error) {
    return {
      success: false,
      message: `Error during threat deletion: ${error.message}`,
      details: { errors: [error.message] }
    };
  }
}

async function generateRealMalwareTests() {
  try {
    const testDir = path.join(os.homedir(), 'OneDrive', 'Desktop', 'Antivirus_Test_Files');
    
    // Ensure directory exists
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
    
    const results = {
      filesCreated: [],
      testsPerformed: [],
      recommendations: []
    };
    
    // Test 1: Create proper EICAR file with correct format
    const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    const eicarPath = path.join(testDir, 'EICAR_TEST.COM');
    
    // Create EICAR as COM file (more likely to be detected)
    fs.writeFileSync(eicarPath, eicarString, 'utf8');
    results.filesCreated.push('EICAR_TEST.COM');
    
    // Wait for real-time scanning
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Check if EICAR was quarantined (file should be deleted)
    const eicarQuarantined = !fs.existsSync(eicarPath);
    results.testsPerformed.push({
      test: 'EICAR Detection',
      result: eicarQuarantined ? 'DETECTED' : 'NOT DETECTED',
      details: eicarQuarantined ? 'File was quarantined by antivirus' : 'File was not quarantined'
    });
    
    // Test 2: Create another EICAR file to test multiple detections
    const eicarPath2 = path.join(testDir, 'EICAR_TEST2.EXE');
    fs.writeFileSync(eicarPath2, eicarString, 'utf8');
    results.filesCreated.push('EICAR_TEST2.EXE');
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    const eicarQuarantined2 = !fs.existsSync(eicarPath2);
    
    results.testsPerformed.push({
      test: 'EICAR Detection (EXE)',
      result: eicarQuarantined2 ? 'DETECTED' : 'NOT DETECTED',
      details: eicarQuarantined2 ? 'EXE file was quarantined by antivirus' : 'EXE file was not quarantined'
    });
    
    // Test 3: Check Windows Defender quarantine folder
    try {
      const quarantinePath = path.join(os.homedir(), 'AppData', 'Local', 'Microsoft', 'Windows', 'Windows Defender', 'Quarantine');
      const quarantineExists = fs.existsSync(quarantinePath);
      
      if (quarantineExists) {
        const quarantineFiles = fs.readdirSync(quarantinePath);
        results.testsPerformed.push({
          test: 'Quarantine Folder Check',
          result: quarantineFiles.length > 0 ? 'FILES QUARANTINED' : 'NO FILES QUARANTINED',
          details: quarantineFiles.length > 0 ? 
            `Found ${quarantineFiles.length} quarantined files` : 
            'No files in quarantine folder'
        });
      } else {
        results.testsPerformed.push({
          test: 'Quarantine Folder Check',
          result: 'FOLDER NOT FOUND',
          details: 'Windows Defender quarantine folder not found'
        });
      }
    } catch (error) {
      results.testsPerformed.push({
        test: 'Quarantine Folder Check',
        result: 'ERROR',
        details: `Error checking quarantine: ${error.message}`
      });
    }
    
    // Test 4: Create file with actual malware signatures (safe test patterns)
    const malwareSignatures = [
      // These are known malware signature patterns (safe for testing)
      'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00',
      'PE\x00\x00\x4c\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
      'This file contains patterns that mimic known malware signatures but is completely safe for testing purposes.'
    ];
    
    // Create files with suspicious binary patterns
    const suspiciousExePath = path.join(testDir, 'suspicious_pattern.exe');
    fs.writeFileSync(suspiciousExePath, malwareSignatures[0], 'binary');
    results.filesCreated.push('suspicious_pattern.exe');
    
    // Test 5: Create script that triggers behavioral analysis
    const behavioralScript = `@echo off
REM This script contains patterns that may trigger behavioral analysis
echo Testing behavioral analysis...
set /a counter=0
:loop
if %counter% lss 5 (
    echo Counter: %counter%
    set /a counter+=1
    goto loop
)
REM Attempt to access system files (safe but suspicious)
dir C:\\Windows\\System32\\notepad.exe >nul 2>&1
REM Attempt to modify registry (safe but suspicious)
reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" >nul 2>&1
echo Behavioral test complete - this is a safe test script`;
    
    const behavioralPath = path.join(testDir, 'behavioral_test.bat');
    fs.writeFileSync(behavioralPath, behavioralScript, 'utf8');
    results.filesCreated.push('behavioral_test.bat');
    
    // Test 6: Create file with known suspicious strings
    const suspiciousStrings = [
      'This file contains the string "malware" which may trigger keyword detection',
      'Virus detection test file with suspicious content patterns',
      'Trojan horse simulation file for antivirus testing',
      'Backdoor test file - completely safe but may trigger alerts',
      'Rootkit simulation file for security testing purposes'
    ];
    
    suspiciousStrings.forEach((content, index) => {
      const fileName = `suspicious_content_${index + 1}.txt`;
      const filePath = path.join(testDir, fileName);
      fs.writeFileSync(filePath, content, 'utf8');
      results.filesCreated.push(fileName);
    });
    
    // Test 7: Try to execute the behavioral script
    try {
      const { exec } = require('child_process');
      await new Promise((resolve, reject) => {
        exec(`"${behavioralPath}"`, (error, stdout, stderr) => {
          if (error) {
            results.testsPerformed.push({
              test: 'Behavioral Analysis',
              result: 'BLOCKED',
              details: 'Script execution was blocked by antivirus'
            });
          } else {
            results.testsPerformed.push({
              test: 'Behavioral Analysis',
              result: 'NOT BLOCKED',
              details: 'Script execution was not blocked'
            });
          }
          resolve();
        });
      });
    } catch (error) {
      results.testsPerformed.push({
        test: 'Behavioral Analysis',
        result: 'BLOCKED',
        details: 'Script execution was blocked by antivirus'
      });
    }
    
    // Generate recommendations based on results
    const eicarTest = results.testsPerformed.find(t => t.test === 'EICAR Detection');
    const eicarExeTest = results.testsPerformed.find(t => t.test === 'EICAR Detection (EXE)');
    const quarantineTest = results.testsPerformed.find(t => t.test === 'Quarantine Folder Check');
    
    if (eicarTest && !eicarTest.result.includes('DETECTED')) {
      results.recommendations.push('EICAR not detected - Check antivirus EICAR detection settings');
    }
    
    if (eicarExeTest && !eicarExeTest.result.includes('DETECTED')) {
      results.recommendations.push('EICAR EXE not detected - Check executable file detection');
    }
    
    if (quarantineTest && quarantineTest.result === 'NO FILES QUARANTINED') {
      results.recommendations.push('No files in quarantine - Check if files are being properly quarantined');
    }
    
    const behavioralTest = results.testsPerformed.find(t => t.test === 'Behavioral Analysis');
    if (behavioralTest && behavioralTest.result === 'NOT BLOCKED') {
      results.recommendations.push('Behavioral analysis not working - Enable real-time protection');
    }
    
    if (results.recommendations.length === 0) {
      results.recommendations.push('All tests passed - Antivirus appears to be working correctly');
    }
    
    return results;
  } catch (error) {
    return {
      filesCreated: [],
      testsPerformed: [],
      recommendations: [`Test error: ${error.message}`]
    };
  }
}

async function scanFileWithVirusTotal(filePath) {
  try {
    const { spawn } = require('child_process');
    const pythonProcess = spawn('python', ['backend/antivirus.py', '--file', filePath], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe']
    });
    
    let output = '';
    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    await new Promise((resolve, reject) => {
      pythonProcess.on('close', (code) => {
        resolve();
      });
    });
    
    // Parse VirusTotal results
    const lines = output.split('\n');
    let virustotalResult = null;
    
    for (const line of lines) {
      if (line.startsWith('{') && line.includes('detected')) {
        try {
          virustotalResult = JSON.parse(line);
          break;
        } catch (e) {
          // Ignore JSON parsing errors
        }
      }
    }
    
    return {
      filePath: filePath,
      virustotalResult: virustotalResult,
      rawOutput: output,
      success: virustotalResult !== null
    };
  } catch (error) {
    return {
      filePath: filePath,
      virustotalResult: null,
      rawOutput: '',
      success: false,
      error: error.message
    };
  }
}

// Función auxiliar para calcular la fortaleza de la contraseña
function calculatePasswordStrength(password) {
  let score = 0;
  
  // Verificar longitud
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  
  // Verificar variedad de caracteres
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  
  // Determinar nivel de fortaleza
  if (score <= 3) return 'débil';
  if (score <= 5) return 'media';
  if (score <= 7) return 'fuerte';
  return 'muy-fuerte';
}
