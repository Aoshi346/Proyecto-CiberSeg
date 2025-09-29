const os = require('os');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

class SystemAnalyzer {
  constructor() {
    this.analysisHistory = [];
    this.systemInfo = null;
  }

  async fullSystemAnalysis() {
    try {
      console.log('Iniciando análisis completo del sistema...');
      
      const startTime = Date.now();
      const analysis = {
        system: await this.getDetailedSystemInfo(),
        processes: await this.getProcessList(),
        network: await this.getNetworkConnections(),
        filesystem: await this.getFilesystemInfo(),
        security: await this.getSecurityInfo(),
        performance: await this.getPerformanceInfo()
      };

      const duration = Date.now() - startTime;
      
      const result = {
        success: true,
        analysis: analysis,
        duration: duration,
        timestamp: new Date().toISOString()
      };

      this.analysisHistory.push(result);
      
      return result;
    } catch (error) {
      console.error('Error en análisis completo del sistema:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  }


  async getDetailedSystemInfo() {
    try {
      const systemInfo = {
        // Basic system info
        platform: os.platform(),
        arch: os.arch(),
        hostname: os.hostname(),
        type: os.type(),
        release: os.release(),
        version: os.version(),
        uptime: os.uptime(),
        
        // Memory information
        memory: {
          total: os.totalmem(),
          free: os.freemem(),
          used: os.totalmem() - os.freemem(),
          usage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100
        },
        
        // CPU information
        cpu: {
          cores: os.cpus().length,
          model: os.cpus()[0]?.model || 'Unknown',
          speed: os.cpus()[0]?.speed || 0,
          loadavg: os.loadavg()
        },
        
        // Network interfaces
        networkInterfaces: os.networkInterfaces(),
        
        // User and system paths
        userInfo: os.userInfo(),
        tmpdir: os.tmpdir(),
        homedir: os.homedir(),
        
        // Additional Windows-specific info
        windowsInfo: await this.getWindowsSpecificInfo()
      };

      this.systemInfo = systemInfo;
      return systemInfo;
    } catch (error) {
      console.error('Error obteniendo información detallada del sistema:', error);
      return { error: error.message };
    }
  }

  async getWindowsSpecificInfo() {
    try {
      if (os.platform() !== 'win32') {
        return { platform: 'non-windows' };
      }

      const windowsInfo = {
        // Get Windows version details
        version: await this.getWindowsVersion(),
        
        // Get WiFi information
        wifi: await this.getWiFiInfo(),
        
        // Get disk information
        disks: await this.getDiskInfo(),
        
        // Get system services
        services: await this.getSystemServices(),
        
        // Get installed programs
        programs: await this.getInstalledPrograms()
      };

      return windowsInfo;
    } catch (error) {
      console.error('Error obteniendo información específica de Windows:', error);
      return { error: error.message };
    }
  }

  async getWindowsVersion() {
    try {
      const { stdout } = await execAsync('wmic os get Caption,Version,BuildNumber /value');
      const lines = stdout.split('\n');
      const version = {};
      
      lines.forEach(line => {
        if (line.includes('Caption=')) {
          version.caption = line.split('Caption=')[1]?.trim();
        } else if (line.includes('Version=')) {
          version.version = line.split('Version=')[1]?.trim();
        } else if (line.includes('BuildNumber=')) {
          version.buildNumber = line.split('BuildNumber=')[1]?.trim();
        }
      });
      
      return version;
    } catch (error) {
      return { error: error.message };
    }
  }

  async getWiFiInfo() {
    try {
      const { stdout } = await execAsync('netsh wlan show profiles');
      const profiles = [];
      const lines = stdout.split('\n');
      
      lines.forEach(line => {
        if (line.includes('All User Profile')) {
          const profileName = line.split(':')[1]?.trim();
          if (profileName) {
            profiles.push(profileName);
          }
        }
      });

      // Get current WiFi connection
      const { stdout: currentWifi } = await execAsync('netsh wlan show interfaces');
      const wifiInfo = {
        profiles: profiles,
        currentConnection: this.parseCurrentWiFiConnection(currentWifi)
      };

      return wifiInfo;
    } catch (error) {
      return { error: error.message };
    }
  }

  parseCurrentWiFiConnection(stdout) {
    const lines = stdout.split('\n');
    const connection = {};
    
    lines.forEach(line => {
      if (line.includes('SSID')) {
        connection.ssid = line.split(':')[1]?.trim();
      } else if (line.includes('Signal')) {
        connection.signal = line.split(':')[1]?.trim();
      } else if (line.includes('Radio type')) {
        connection.radioType = line.split(':')[1]?.trim();
      } else if (line.includes('Authentication')) {
        connection.authentication = line.split(':')[1]?.trim();
      } else if (line.includes('Cipher')) {
        connection.cipher = line.split(':')[1]?.trim();
      }
    });
    
    return connection;
  }

  async getDiskInfo() {
    try {
      const { stdout } = await execAsync('wmic logicaldisk get size,freespace,caption,volumename /value');
      const disks = [];
      const lines = stdout.split('\n');
      let currentDisk = {};
      
      lines.forEach(line => {
        if (line.includes('Caption=')) {
          if (Object.keys(currentDisk).length > 0) {
            disks.push(currentDisk);
          }
          currentDisk = { caption: line.split('Caption=')[1]?.trim() };
        } else if (line.includes('Size=')) {
          currentDisk.size = parseInt(line.split('Size=')[1]?.trim()) || 0;
        } else if (line.includes('FreeSpace=')) {
          currentDisk.freeSpace = parseInt(line.split('FreeSpace=')[1]?.trim()) || 0;
        } else if (line.includes('VolumeName=')) {
          currentDisk.volumeName = line.split('VolumeName=')[1]?.trim();
        }
      });
      
      if (Object.keys(currentDisk).length > 0) {
        disks.push(currentDisk);
      }
      
      return disks;
    } catch (error) {
      return { error: error.message };
    }
  }

  async getSystemServices() {
    try {
      const { stdout } = await execAsync('sc query state= all | findstr "SERVICE_NAME"');
      const services = stdout.split('\n').filter(line => line.trim());
      return {
        total: services.length,
        services: services.slice(0, 10) // Limit to first 10
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async getInstalledPrograms() {
    try {
      const { stdout } = await execAsync('wmic product get name,version /value | findstr "Name="');
      const programs = stdout.split('\n').filter(line => line.trim()).slice(0, 10);
      return {
        total: programs.length,
        programs: programs
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async getBasicSystemInfo() {
    return {
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      uptime: os.uptime(),
      totalmem: os.totalmem(),
      freemem: os.freemem(),
      cpus: os.cpus().length
    };
  }

  async getProcessList() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('tasklist /fo csv');
        const processes = this.parseWindowsProcessList(stdout);
        return {
          total: processes.length,
          processes: processes.slice(0, 50), // Limitar a 50 procesos
          platform: 'windows'
        };
      } else {
        const { stdout } = await execAsync('ps aux');
        const processes = this.parseUnixProcessList(stdout);
        return {
          total: processes.length,
          processes: processes.slice(0, 50), // Limitar a 50 procesos
          platform: 'unix'
        };
      }
    } catch (error) {
      console.error('Error obteniendo lista de procesos:', error);
      return { error: error.message };
    }
  }

  async getNetworkConnections() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('netstat -an');
        const connections = this.parseWindowsNetstat(stdout);
        return {
          total: connections.length,
          connections: connections,
          platform: 'windows'
        };
      } else {
        const { stdout } = await execAsync('netstat -an');
        const connections = this.parseUnixNetstat(stdout);
        return {
          total: connections.length,
          connections: connections,
          platform: 'unix'
        };
      }
    } catch (error) {
      console.error('Error obteniendo conexiones de red:', error);
      return { error: error.message };
    }
  }

  async getFilesystemInfo() {
    try {
      const drives = [];
      
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('wmic logicaldisk get size,freespace,caption');
        const driveInfo = this.parseWindowsDrives(stdout);
        drives.push(...driveInfo);
      } else {
        const { stdout } = await execAsync('df -h');
        const driveInfo = this.parseUnixDrives(stdout);
        drives.push(...driveInfo);
      }

      return {
        drives: drives,
        totalDrives: drives.length,
        totalSpace: drives.reduce((sum, drive) => sum + drive.total, 0),
        freeSpace: drives.reduce((sum, drive) => sum + drive.free, 0)
      };
    } catch (error) {
      console.error('Error obteniendo información del sistema de archivos:', error);
      return { error: error.message };
    }
  }

  async getSecurityInfo() {
    try {
      const security = {
        users: await this.getUserAccounts(),
        services: await this.getRunningServices(),
        firewall: await this.getFirewallStatus(),
        antivirus: await this.getAntivirusStatus(),
        updates: await this.getUpdateStatus()
      };

      return security;
    } catch (error) {
      console.error('Error obteniendo información de seguridad:', error);
      return { error: error.message };
    }
  }

  async getBasicSecurityInfo() {
    return {
      users: await this.getUserAccounts(),
      firewall: await this.getFirewallStatus(),
      antivirus: await this.getAntivirusStatus()
    };
  }

  async getPerformanceInfo() {
    try {
      const performance = {
        cpu: {
          usage: await this.getCpuUsage(),
          loadavg: os.loadavg(),
          cores: os.cpus().length
        },
        memory: {
          total: os.totalmem(),
          free: os.freemem(),
          used: os.totalmem() - os.freemem(),
          usage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100
        },
        disk: await this.getDiskUsage()
      };

      return performance;
    } catch (error) {
      console.error('Error obteniendo información de rendimiento:', error);
      return { error: error.message };
    }
  }

  async getBasicPerformanceInfo() {
    return {
      cpu: {
        loadavg: os.loadavg(),
        cores: os.cpus().length
      },
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        usage: ((os.totalmem() - os.freemem()) / os.totalmem()) * 100
      }
    };
  }

  async getUserAccounts() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('net user');
        return this.parseWindowsUsers(stdout);
      } else {
        const { stdout } = await execAsync('cat /etc/passwd');
        return this.parseUnixUsers(stdout);
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  async getRunningServices() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('sc query state= all');
        return this.parseWindowsServices(stdout);
      } else {
        const { stdout } = await execAsync('systemctl list-units --type=service');
        return this.parseUnixServices(stdout);
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  async getFirewallStatus() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('netsh advfirewall show allprofiles state');
        return this.parseWindowsFirewall(stdout);
      } else {
        const { stdout } = await execAsync('ufw status');
        return this.parseUnixFirewall(stdout);
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  async getAntivirusStatus() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState');
        return this.parseWindowsAntivirus(stdout);
      } else {
        return { status: 'unknown', platform: 'unix' };
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  async getUpdateStatus() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('wmic qfe list');
        return this.parseWindowsUpdates(stdout);
      } else {
        const { stdout } = await execAsync('apt list --upgradable 2>/dev/null || yum check-update 2>/dev/null');
        return this.parseUnixUpdates(stdout);
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  async getCpuUsage() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('wmic cpu get loadpercentage /value');
        return this.parseWindowsCpuUsage(stdout);
      } else {
        const { stdout } = await execAsync('top -bn1 | grep "Cpu(s)"');
        return this.parseUnixCpuUsage(stdout);
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  async getDiskUsage() {
    try {
      if (os.platform() === 'win32') {
        const { stdout } = await execAsync('wmic logicaldisk get size,freespace,caption');
        return this.parseWindowsDiskUsage(stdout);
      } else {
        const { stdout } = await execAsync('df -h');
        return this.parseUnixDiskUsage(stdout);
      }
    } catch (error) {
      return { error: error.message };
    }
  }

  // Parsers para Windows
  parseWindowsProcessList(stdout) {
    const lines = stdout.split('\n').slice(1); // Skip header
    return lines.map(line => {
      const parts = line.split(',').map(part => part.replace(/"/g, '').trim());
      return {
        name: parts[0],
        pid: parts[1],
        sessionName: parts[2],
        sessionNumber: parts[3],
        memoryUsage: parts[4]
      };
    }).filter(proc => proc.name);
  }

  parseWindowsNetstat(stdout) {
    const lines = stdout.split('\n');
    return lines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        return {
          protocol: parts[0],
          localAddress: parts[1],
          foreignAddress: parts[2],
          state: parts[3]
        };
      }
      return null;
    }).filter(conn => conn);
  }

  parseWindowsDrives(stdout) {
    const lines = stdout.split('\n').slice(1);
    return lines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        return {
          drive: parts[0],
          total: parseInt(parts[1]) || 0,
          free: parseInt(parts[2]) || 0
        };
      }
      return null;
    }).filter(drive => drive);
  }

  parseWindowsUsers(stdout) {
    const lines = stdout.split('\n');
    return lines.filter(line => line.trim() && !line.includes('User accounts for'));
  }

  parseWindowsServices(stdout) {
    const lines = stdout.split('\n');
    return lines.filter(line => line.includes('SERVICE_NAME:'));
  }

  parseWindowsFirewall(stdout) {
    return {
      status: stdout.includes('ON') ? 'enabled' : 'disabled',
      profiles: stdout.split('\n').filter(line => line.includes('Profile'))
    };
  }

  parseWindowsAntivirus(stdout) {
    const lines = stdout.split('\n');
    return lines.filter(line => line.trim() && !line.includes('DisplayName'));
  }

  parseWindowsUpdates(stdout) {
    const lines = stdout.split('\n');
    return lines.filter(line => line.trim() && !line.includes('HotFixID'));
  }

  parseWindowsCpuUsage(stdout) {
    const match = stdout.match(/LoadPercentage=(\d+)/);
    return match ? parseInt(match[1]) : 0;
  }

  parseWindowsDiskUsage(stdout) {
    return this.parseWindowsDrives(stdout);
  }

  // Parsers para Unix/Linux
  parseUnixProcessList(stdout) {
    const lines = stdout.split('\n').slice(1);
    return lines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 11) {
        return {
          user: parts[0],
          pid: parts[1],
          cpu: parts[2],
          mem: parts[3],
          vsz: parts[4],
          rss: parts[5],
          tty: parts[6],
          stat: parts[7],
          start: parts[8],
          time: parts[9],
          command: parts.slice(10).join(' ')
        };
      }
      return null;
    }).filter(proc => proc);
  }

  parseUnixNetstat(stdout) {
    const lines = stdout.split('\n');
    return lines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 6) {
        return {
          protocol: parts[0],
          recvQ: parts[1],
          sendQ: parts[2],
          localAddress: parts[3],
          foreignAddress: parts[4],
          state: parts[5]
        };
      }
      return null;
    }).filter(conn => conn);
  }

  parseUnixDrives(stdout) {
    const lines = stdout.split('\n').slice(1);
    return lines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 6) {
        return {
          filesystem: parts[0],
          size: parts[1],
          used: parts[2],
          available: parts[3],
          usePercent: parts[4],
          mounted: parts[5]
        };
      }
      return null;
    }).filter(drive => drive);
  }

  parseUnixUsers(stdout) {
    const lines = stdout.split('\n');
    return lines.map(line => {
      const parts = line.split(':');
      if (parts.length >= 7) {
        return {
          username: parts[0],
          password: parts[1],
          uid: parts[2],
          gid: parts[3],
          gecos: parts[4],
          home: parts[5],
          shell: parts[6]
        };
      }
      return null;
    }).filter(user => user);
  }

  parseUnixServices(stdout) {
    const lines = stdout.split('\n');
    return lines.filter(line => line.trim() && !line.includes('UNIT'));
  }

  parseUnixFirewall(stdout) {
    return {
      status: stdout.includes('active') ? 'enabled' : 'disabled',
      rules: stdout.split('\n').filter(line => line.trim())
    };
  }

  parseUnixCpuUsage(stdout) {
    const match = stdout.match(/(\d+\.\d+)%us/);
    return match ? parseFloat(match[1]) : 0;
  }

  parseUnixDiskUsage(stdout) {
    return this.parseUnixDrives(stdout);
  }

  async generateSystemReport() {
    try {
      const analysis = await this.fullSystemAnalysis();
      
      const report = {
        title: 'Reporte de Análisis del Sistema',
        generated: new Date().toISOString(),
        system: analysis.analysis.system,
        summary: {
          totalProcesses: analysis.analysis.processes.total,
          networkConnections: analysis.analysis.network.total,
          drives: analysis.analysis.filesystem.totalDrives,
          users: analysis.analysis.security.users.length,
          services: analysis.analysis.security.services.length
        },
        recommendations: this.generateRecommendations(analysis.analysis)
      };

      // Generate TXT report content
      const txtContent = this.generateTxtReport(report);
      
      // Save to desktop
      const desktopPath = path.join(os.homedir(), 'Desktop');
      const fileName = `Reporte_Sistema_${new Date().toISOString().split('T')[0].replace(/-/g, '_')}.txt`;
      const filePath = path.join(desktopPath, fileName);
      
      fs.writeFileSync(filePath, txtContent, 'utf8');

      return {
        success: true,
        report: report,
        filePath: filePath,
        fileName: fileName,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error generando reporte del sistema:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  }

  generateTxtReport(report) {
    const lines = [];
    
    // Header
    lines.push('='.repeat(80));
    lines.push(`                    ${report.title}`);
    lines.push('='.repeat(80));
    lines.push(`Generado: ${new Date(report.generated).toLocaleString('es-ES')}`);
    lines.push('');
    
    // System Information
    lines.push('INFORMACIÓN DEL SISTEMA');
    lines.push('-'.repeat(40));
    if (report.system.windowsInfo?.version?.caption) {
      lines.push(`Sistema Operativo: ${report.system.windowsInfo.version.caption}`);
      lines.push(`Versión: ${report.system.windowsInfo.version.version}`);
      lines.push(`Build: ${report.system.windowsInfo.version.buildNumber}`);
    } else {
      lines.push(`Sistema Operativo: ${report.system.platform} ${report.system.release}`);
    }
    lines.push(`Arquitectura: ${report.system.arch}`);
    lines.push(`Hostname: ${report.system.hostname}`);
    lines.push(`Tiempo Activo: ${this.formatUptime(report.system.uptime)}`);
    lines.push('');
    
    // Hardware Information
    lines.push('INFORMACIÓN DE HARDWARE');
    lines.push('-'.repeat(40));
    lines.push(`CPU: ${report.system.cpu?.model || 'No disponible'}`);
    lines.push(`Núcleos: ${report.system.cpu?.cores || 'No disponible'}`);
    lines.push(`Memoria Total: ${this.formatBytes(report.system.memory?.total || 0)}`);
    lines.push(`Memoria Libre: ${this.formatBytes(report.system.memory?.free || 0)}`);
    lines.push(`Uso de Memoria: ${report.system.memory?.usage?.toFixed(2) || '0'}%`);
    lines.push('');
    
    // Network Information
    lines.push('INFORMACIÓN DE RED');
    lines.push('-'.repeat(40));
    if (report.system.windowsInfo?.wifi?.currentConnection?.ssid) {
      const wifi = report.system.windowsInfo.wifi.currentConnection;
      lines.push(`WiFi: Conectado`);
      lines.push(`SSID: ${wifi.ssid}`);
      lines.push(`Seguridad: ${wifi.authentication || 'No disponible'}`);
      lines.push(`Señal: ${wifi.signal || 'No disponible'}`);
    } else {
      lines.push(`WiFi: Desconectado`);
    }
    lines.push('');
    
    // Storage Information
    lines.push('INFORMACIÓN DE ALMACENAMIENTO');
    lines.push('-'.repeat(40));
    if (report.system.windowsInfo?.disks) {
      report.system.windowsInfo.disks.forEach(disk => {
        if (disk.caption && disk.size > 0) {
          const used = disk.size - disk.freeSpace;
          const usagePercent = ((used / disk.size) * 100).toFixed(1);
          lines.push(`${disk.caption} (${disk.volumeName || 'Sin nombre'}):`);
          lines.push(`  Total: ${this.formatBytes(disk.size)}`);
          lines.push(`  Usado: ${this.formatBytes(used)}`);
          lines.push(`  Libre: ${this.formatBytes(disk.freeSpace)}`);
          lines.push(`  Uso: ${usagePercent}%`);
          lines.push('');
        }
      });
    }
    
    // Summary
    lines.push('RESUMEN DEL SISTEMA');
    lines.push('-'.repeat(40));
    lines.push(`Procesos Activos: ${report.summary.totalProcesses}`);
    lines.push(`Conexiones de Red: ${report.summary.networkConnections}`);
    lines.push(`Unidades de Disco: ${report.summary.drives}`);
    lines.push(`Usuarios del Sistema: ${report.summary.users}`);
    lines.push(`Servicios del Sistema: ${report.summary.services}`);
    lines.push('');
    
    // Security Recommendations
    lines.push('RECOMENDACIONES DE SEGURIDAD');
    lines.push('-'.repeat(40));
    if (report.recommendations && report.recommendations.length > 0) {
      report.recommendations.forEach((rec, index) => {
        lines.push(`${index + 1}. ${rec}`);
      });
    } else {
      lines.push('No se encontraron problemas de seguridad críticos.');
    }
    lines.push('');
    
    // Footer
    lines.push('='.repeat(80));
    lines.push('Reporte generado por CiberSeg - Sistema de Análisis de Seguridad');
    lines.push('='.repeat(80));
    
    return lines.join('\n');
  }

  formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) {
      return `${days} días, ${hours} horas, ${minutes} minutos`;
    } else if (hours > 0) {
      return `${hours} horas, ${minutes} minutos`;
    } else {
      return `${minutes} minutos`;
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  generateRecommendations(analysis) {
    const recommendations = [];

    // Recomendaciones de memoria
    if (analysis.performance.memory.usage > 80) {
      recommendations.push('Uso de memoria alto - considerar cerrar aplicaciones innecesarias');
    }

    // Recomendaciones de CPU
    if (analysis.performance.cpu.loadavg[0] > 2) {
      recommendations.push('Carga del sistema alta - revisar procesos activos');
    }

    // Recomendaciones de seguridad
    if (analysis.security.firewall.status === 'disabled') {
      recommendations.push('Firewall deshabilitado - habilitar para mayor seguridad');
    }

    return recommendations;
  }

  getAnalysisHistory() {
    return this.analysisHistory;
  }

  clearAnalysisHistory() {
    this.analysisHistory = [];
    return { success: true, message: 'Historial de análisis del sistema limpiado' };
  }
}

module.exports = SystemAnalyzer;
