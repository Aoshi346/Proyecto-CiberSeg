const { app, BrowserWindow, ipcMain, session, Menu } = require('electron');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const fs = require('fs');

// Proceso global del keylogger
let keyloggerProcess = null;
let keyloggerStatus = {
  isRunning: false,
  startTime: null,
  logFile: path.join(__dirname, 'system_log.txt')
};

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
      partition: 'persist:ciberseg'
    },
    show: false,
    autoHideMenuBar: true
  });
  
  // Limpiar cachés al inicio para evitar problemas de permisos residuales
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
  // Eliminar el menú global de la aplicación (Archivo/Editar/Ver...)
  try { Menu.setApplicationMenu(null); } catch (_) {}
  createWindow();
  setupIPC();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
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
