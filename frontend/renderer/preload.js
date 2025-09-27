// Preload script para exposición de API segura
const { contextBridge, ipcRenderer } = require('electron');

// Exponer APIs seguras al proceso renderer
contextBridge.exposeInMainWorld('electronAPI', {
  // Funciones relacionadas con la seguridad
  scanVulnerabilities: () => ipcRenderer.invoke('scan-vulnerabilities'),
  generatePassword: (options) => ipcRenderer.invoke('generate-password', options),
  monitorNetwork: () => ipcRenderer.invoke('monitor-network'),
  forensicAnalysis: (filePath) => ipcRenderer.invoke('forensic-analysis', filePath),
  
  // Funciones del sistema
  getSystemInfo: () => ipcRenderer.invoke('get-system-info'),
  getSecurityStatus: () => ipcRenderer.invoke('get-security-status'),
  
  // Eventos
  onSecurityAlert: (callback) => ipcRenderer.on('security-alert', callback),
  onNetworkEvent: (callback) => ipcRenderer.on('network-event', callback),
  
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
