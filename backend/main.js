const { app, BrowserWindow, ipcMain, session, Menu } = require('electron');
const path = require('path');
const os = require('os');

// Set userData path early to avoid OneDrive permission issues
try {
  const tempBase = path.join(os.tmpdir(), 'ciberseg');
  app.setPath('userData', tempBase);
} catch (e) {
  console.warn('Failed setting userData path', e);
}

// Reduce cache-related issues
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
  
  // Clear caches on start to avoid residual permission issues
  win.webContents.session.clearCache();
  session.defaultSession?.clearCache();

  // Hide the menu bar for this window explicitly
  win.setMenuBarVisibility(false);
  
  win.loadFile(path.join(__dirname, '..', 'frontend', 'renderer', 'index.html'));
  
  win.once('ready-to-show', () => {
    win.show();
  });
}

app.whenReady().then(() => {
  // Remove the global application menu (File/Edit/View...)
  try { Menu.setApplicationMenu(null); } catch (_) {}
  createWindow();
  setupIPC();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// IPC Handlers for security functions
function setupIPC() {
  // Vulnerability scanning
  ipcMain.handle('scan-vulnerabilities', async () => {
    console.log('Starting vulnerability scan...');
    // Simulate scan process
    return {
      status: 'completed',
      vulnerabilities: [
        { id: 1, severity: 'high', description: 'Outdated SSL certificate' },
        { id: 2, severity: 'medium', description: 'Weak password policy' },
        { id: 3, severity: 'low', description: 'Missing security headers' }
      ],
      timestamp: new Date().toISOString()
    };
  });

  // Password generation
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

  // Network monitoring
  ipcMain.handle('monitor-network', async () => {
    console.log('Starting network monitoring...');
    return {
      status: 'active',
      connections: 15,
      threats: 0,
      bandwidth: '125.6 Mbps',
      timestamp: new Date().toISOString()
    };
  });

  // Forensic analysis
  ipcMain.handle('forensic-analysis', async (event, filePath) => {
    console.log(`Starting forensic analysis of: ${filePath}`);
    return {
      status: 'completed',
      fileHash: 'sha256:abc123...',
      fileType: 'executable',
      suspicious: false,
      metadata: {
        created: '2024-01-15T10:30:00Z',
        modified: '2024-01-15T10:30:00Z',
        size: '2.5 MB'
      },
      timestamp: new Date().toISOString()
    };
  });

  // System information
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

  // Security status
  ipcMain.handle('get-security-status', async () => {
    return {
      overall: 'secure',
      antivirus: 'active',
      firewall: 'enabled',
      updates: 'current',
      vulnerabilities: 3,
      lastScan: new Date().toISOString(),
      timestamp: new Date().toISOString()
    };
  });
}

// Helper function to calculate password strength
function calculatePasswordStrength(password) {
  let score = 0;
  
  // Length check
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  
  // Character variety
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  
  // Determine strength level
  if (score <= 3) return 'weak';
  if (score <= 5) return 'medium';
  if (score <= 7) return 'strong';
  return 'very-strong';
}
