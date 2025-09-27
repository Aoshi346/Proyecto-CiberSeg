const { app, BrowserWindow, ipcMain, session, Menu } = require('electron');
const path = require('path');
const os = require('os');

// Poner la ruta de userData para evitar problemas con OneDrive
try {
  const tempBase = path.join(os.tmpdir(), 'ciberseg');
  app.setPath('userData', tempBase);
} catch (e) {
  console.warn('Failed setting userData path', e);
}

// Reducir problemas de cache
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
  
  // Limpiar caches al inicio para evitar problemas de permisos residuales
  win.webContents.session.clearCache();
  session.defaultSession?.clearCache();

  // Ocultar la barra de menú para esta ventana explícitamente
  win.setMenuBarVisibility(false);
  
  // Load the frontend HTML file
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
