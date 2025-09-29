const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

class FileAnalyzer {
  constructor() {
    this.analysisHistory = [];
    this.supportedFormats = {
      images: ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg', '.ico'],
      documents: ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'],
      archives: ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso', '.dmg', '.arj', '.ace'],
      executables: ['.exe', '.msi', '.dll', '.sys', '.scr', '.pif', '.com', '.bat', '.cmd'],
      scripts: ['.js', '.py', '.bat', '.cmd', '.ps1', '.vbs', '.sh', '.php', '.html', '.css'],
      multimedia: ['.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac', '.mov', '.wmv', '.m4a', '.aac']
    };
  }

  async analyzeFile(filePath, analysisType = 'full') {
    try {
      if (!fs.existsSync(filePath)) {
        return { success: false, message: 'Archivo no encontrado' };
      }

      console.log(`Analizando archivo: ${filePath}`);
      
      const fileStats = fs.statSync(filePath);
      const analysis = {
        basic: await this.basicAnalysis(filePath, fileStats),
        hash: await this.hashAnalysis(filePath),
        metadata: await this.metadataAnalysis(filePath, fileStats),
        content: null,
        security: null
      };

      // Análisis de contenido según el tipo de archivo
      if (analysisType === 'full' || analysisType === 'content') {
        analysis.content = await this.contentAnalysis(filePath, fileStats);
      }

      // Análisis de seguridad
      if (analysisType === 'full' || analysisType === 'security') {
        analysis.security = await this.securityAnalysis(filePath, fileStats);
      }

      const result = {
        success: true,
        filePath: filePath,
        analysisType: analysisType,
        analysis: analysis,
        timestamp: new Date().toISOString(),
        duration: Date.now() - Date.now() // Placeholder for actual duration
      };

      // Guardar en historial
      this.analysisHistory.push(result);
      
      return result;
    } catch (error) {
      console.error('Error analizando archivo:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  }

  async analyzeFolder(folderPath, analysisType = 'full') {
    try {
      if (!fs.existsSync(folderPath)) {
        return { success: false, message: 'Carpeta no encontrada' };
      }

      console.log(`Analizando carpeta: ${folderPath}`);
      
      const folderStats = fs.statSync(folderPath);
      const files = fs.readdirSync(folderPath, { withFileTypes: true });
      
      const analysis = {
        folderPath: folderPath,
        totalFiles: files.length,
        files: [],
        summary: {
          byType: {},
          bySize: { small: 0, medium: 0, large: 0 },
          suspicious: 0
        }
      };

      for (const file of files) {
        const filePath = path.join(folderPath, file.name);
        
        if (file.isFile()) {
          const fileAnalysis = await this.analyzeFile(filePath, analysisType);
          if (fileAnalysis.success) {
            analysis.files.push(fileAnalysis);
            
            // Actualizar resumen
            const extension = path.extname(file.name).toLowerCase();
            analysis.summary.byType[extension] = (analysis.summary.byType[extension] || 0) + 1;
            
            const size = fileAnalysis.analysis.basic.size;
            if (size < 1024 * 1024) analysis.summary.bySize.small++;
            else if (size < 10 * 1024 * 1024) analysis.summary.bySize.medium++;
            else analysis.summary.bySize.large++;
            
            if (fileAnalysis.analysis.security?.riskLevel === 'high' || 
                fileAnalysis.analysis.security?.riskLevel === 'critical') {
              analysis.summary.suspicious++;
            }
          }
        }
      }

      const result = {
        success: true,
        folderPath: folderPath,
        analysisType: analysisType,
        analysis: analysis,
        timestamp: new Date().toISOString()
      };

      this.analysisHistory.push(result);
      
      return result;
    } catch (error) {
      console.error('Error analizando carpeta:', error);
      return { success: false, message: `Error: ${error.message}` };
    }
  }

  async basicAnalysis(filePath, fileStats) {
    return {
      name: path.basename(filePath),
      extension: path.extname(filePath),
      size: fileStats.size,
      sizeFormatted: this.formatFileSize(fileStats.size),
      type: this.getFileType(path.extname(filePath)),
      created: fileStats.birthtime,
      modified: fileStats.mtime,
      accessed: fileStats.atime,
      permissions: fileStats.mode.toString(8),
      isHidden: path.basename(filePath).startsWith('.'),
      isExecutable: this.isExecutable(filePath)
    };
  }

  async hashAnalysis(filePath) {
    try {
      const fileContent = fs.readFileSync(filePath);
      
      return {
        md5: crypto.createHash('md5').update(fileContent).digest('hex'),
        sha1: crypto.createHash('sha1').update(fileContent).digest('hex'),
        sha256: crypto.createHash('sha256').update(fileContent).digest('hex'),
        sha512: crypto.createHash('sha512').update(fileContent).digest('hex')
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async metadataAnalysis(filePath, fileStats) {
    const metadata = {
      basic: {
        name: path.basename(filePath),
        directory: path.dirname(filePath),
        extension: path.extname(filePath),
        size: fileStats.size,
        created: fileStats.birthtime,
        modified: fileStats.mtime,
        accessed: fileStats.atime
      },
      extended: {}
    };

    // Análisis extendido según el tipo de archivo
    const extension = path.extname(filePath).toLowerCase();
    
    try {
      if (this.supportedFormats.images.includes(extension)) {
        metadata.extended.image = await this.analyzeImageMetadata(filePath);
      } else if (this.supportedFormats.documents.includes(extension)) {
        metadata.extended.document = await this.analyzeDocumentMetadata(filePath);
      } else if (this.supportedFormats.executables.includes(extension)) {
        metadata.extended.executable = await this.analyzeExecutableMetadata(filePath);
      } else if (this.supportedFormats.archives.includes(extension)) {
        metadata.extended.archive = await this.analyzeArchiveMetadata(filePath);
      } else if (this.supportedFormats.multimedia.includes(extension)) {
        metadata.extended.multimedia = await this.analyzeMultimediaMetadata(filePath);
      }
    } catch (error) {
      console.log('Error in extended metadata analysis:', error.message);
      metadata.extended.error = 'Análisis extendido no disponible';
    }

    return metadata;
  }

  async contentAnalysis(filePath, fileStats) {
    const extension = path.extname(filePath).toLowerCase();
    const content = {
      type: this.getFileType(extension),
      encoding: 'unknown',
      language: 'unknown',
      lines: 0,
      words: 0,
      characters: 0
    };

    try {
      // Leer contenido del archivo
      const fileContent = fs.readFileSync(filePath, 'utf8');
      
      content.encoding = 'utf8';
      content.lines = fileContent.split('\n').length;
      content.words = fileContent.split(/\s+/).filter(word => word.length > 0).length;
      content.characters = fileContent.length;

      // Detectar lenguaje de programación
      if (this.supportedFormats.scripts.includes(extension)) {
        content.language = this.detectProgrammingLanguage(extension, fileContent);
      }

      // Análisis de contenido sospechoso
      content.suspiciousPatterns = this.detectSuspiciousPatterns(fileContent);
      
    } catch (error) {
      content.error = error.message;
    }

    return content;
  }

  async securityAnalysis(filePath, fileStats) {
    const security = {
      riskLevel: 'low',
      threats: [],
      vulnerabilities: [],
      recommendations: []
    };

    try {
      // Análisis de extensiones peligrosas
      const extension = path.extname(filePath).toLowerCase();
      if (this.supportedFormats.executables.includes(extension)) {
        security.threats.push({
          type: 'executable_file',
          severity: 'medium',
          description: 'Archivo ejecutable detectado'
        });
      }

      // Análisis de tamaño sospechoso
      if (fileStats.size > 100 * 1024 * 1024) {
        security.threats.push({
          type: 'large_file',
          severity: 'low',
          description: 'Archivo de gran tamaño'
        });
      }

      // Análisis de permisos
      const permissions = fileStats.mode.toString(8);
      if (permissions.includes('777') || permissions.includes('666')) {
        security.vulnerabilities.push({
          type: 'permissive_permissions',
          severity: 'medium',
          description: 'Permisos demasiado permisivos'
        });
      }

      // Detectar archivo EICAR
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        if (content.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')) {
          security.threats.push({
            type: 'eicar_test_file',
            severity: 'critical',
            description: 'Archivo de prueba EICAR detectado'
          });
        }
      } catch (error) {
        // Ignore binary files
      }

      // Detectar archivos sospechosos por nombre
      const fileName = path.basename(filePath).toLowerCase();
      const suspiciousNames = ['virus', 'malware', 'trojan', 'backdoor', 'rootkit', 'keylogger'];
      if (suspiciousNames.some(name => fileName.includes(name))) {
        security.threats.push({
          type: 'suspicious_name',
          severity: 'high',
          description: 'Nombre de archivo sospechoso'
        });
      }

      // Detectar archivos muy pequeños (posibles archivos de prueba)
      if (fileStats.size < 100 && extension === '.com') {
        security.threats.push({
          type: 'small_executable',
          severity: 'high',
          description: 'Archivo ejecutable muy pequeño (posible archivo de prueba)'
        });
      }

      // VirusTotal API Integration
      try {
        const virustotalResult = await this.scanWithVirusTotal(filePath);
        if (virustotalResult.success && virustotalResult.threats.length > 0) {
          security.threats.push(...virustotalResult.threats);
        }
      } catch (error) {
        console.log('VirusTotal scan failed:', error.message);
      }

      // Calcular nivel de riesgo
      security.riskLevel = this.calculateSecurityRisk(security.threats, security.vulnerabilities);

      // Generar recomendaciones
      security.recommendations = this.generateSecurityRecommendations(security);

    } catch (error) {
      security.error = error.message;
    }

    return security;
  }

  async analyzeImageMetadata(filePath) {
    // Análisis básico de metadatos de imagen
    return {
      format: path.extname(filePath).toLowerCase(),
      hasMetadata: false, // Placeholder
      colorSpace: 'unknown',
      compression: 'unknown'
    };
  }

  async analyzeDocumentMetadata(filePath) {
    // Análisis básico de metadatos de documento
    return {
      format: path.extname(filePath).toLowerCase(),
      hasMetadata: false, // Placeholder
      pages: 0,
      author: 'unknown'
    };
  }

  async analyzeExecutableMetadata(filePath) {
    // Análisis básico de metadatos de ejecutable
    return {
      format: path.extname(filePath).toLowerCase(),
      architecture: 'unknown',
      isSigned: false,
      hasDigitalSignature: false
    };
  }

  async analyzeArchiveMetadata(filePath) {
    try {
      const metadata = {};
      const extension = path.extname(filePath).toLowerCase();
      
      // Try to get archive info using different methods
      if (extension === '.zip') {
        try {
          // Escape the file path for PowerShell
          const escapedPath = filePath.replace(/'/g, "''");
          const { stdout } = await execAsync(`powershell "Add-Type -AssemblyName System.IO.Compression.FileSystem; try { [System.IO.Compression.ZipFile]::OpenRead('${escapedPath}').Entries.Count } catch { '0' }"`);
          metadata.fileCount = parseInt(stdout.trim()) || 0;
          metadata.type = 'ZIP Archive';
        } catch (error) {
          console.log('PowerShell ZIP analysis failed:', error.message);
          metadata.type = 'ZIP Archive';
          metadata.note = 'Información detallada no disponible';
        }
      } else if (extension === '.rar') {
        metadata.type = 'RAR Archive';
        metadata.note = 'Información detallada requiere WinRAR';
      } else if (extension === '.7z') {
        metadata.type = '7-Zip Archive';
        metadata.note = 'Información detallada requiere 7-Zip';
      } else if (extension === '.tar' || extension === '.gz' || extension === '.bz2') {
        metadata.type = 'TAR Archive';
        metadata.note = 'Archivo comprimido Unix/Linux';
      } else {
        metadata.type = 'Archive File';
        metadata.note = 'Tipo de archivo comprimido';
      }
      
      return metadata;
    } catch (error) {
      return { error: 'Error analizando metadatos del archivo comprimido' };
    }
  }

  async analyzeMultimediaMetadata(filePath) {
    try {
      const metadata = {};
      const extension = path.extname(filePath).toLowerCase();
      
      if (['.mp3', '.wav', '.flac', '.m4a', '.aac'].includes(extension)) {
        metadata.type = 'Audio File';
        metadata.category = 'Música/Audio';
      } else if (['.mp4', '.avi', '.mkv', '.mov', '.wmv'].includes(extension)) {
        metadata.type = 'Video File';
        metadata.category = 'Video/Multimedia';
      } else {
        metadata.type = 'Multimedia File';
        metadata.category = 'Archivo multimedia';
      }
      
      return metadata;
    } catch (error) {
      return { error: 'Error analizando metadatos del archivo multimedia' };
    }
  }

  detectProgrammingLanguage(extension, content) {
    const languageMap = {
      '.js': 'javascript',
      '.py': 'python',
      '.bat': 'batch',
      '.cmd': 'batch',
      '.ps1': 'powershell',
      '.vbs': 'vbscript'
    };
    
    return languageMap[extension] || 'unknown';
  }

  detectSuspiciousPatterns(content) {
    const patterns = [
      { pattern: /eval\(/gi, name: 'eval_function', severity: 'high' },
      { pattern: /base64_decode\(/gi, name: 'base64_decode', severity: 'medium' },
      { pattern: /shell_exec\(/gi, name: 'shell_exec', severity: 'high' },
      { pattern: /system\(/gi, name: 'system_call', severity: 'high' },
      { pattern: /exec\(/gi, name: 'exec_function', severity: 'high' },
      { pattern: /passthru\(/gi, name: 'passthru_function', severity: 'high' }
    ];

    const detected = [];
    
    for (const { pattern, name, severity } of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        detected.push({
          pattern: name,
          severity: severity,
          count: matches.length,
          description: `Patrón sospechoso detectado: ${name}`
        });
      }
    }

    return detected;
  }

  async scanWithVirusTotal(filePath) {
    try {
      const { spawn } = require('child_process');
      const pythonProcess = spawn('python', ['backend/antivirus.py', 'scan-file', '--file', filePath], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
      });

      return new Promise((resolve, reject) => {
        pythonProcess.on('close', (code) => {
          if (code === 0) {
            try {
              const lines = output.split('\n');
              for (const line of lines) {
                if (line.startsWith('{') && line.includes('success')) {
                  const result = JSON.parse(line);
                  if (result.success && result.threats && result.threats.length > 0) {
                    resolve({
                      success: true,
                      threats: result.threats.map(threat => ({
                        type: 'virustotal_detection',
                        severity: threat.severity || 'medium',
                        description: `VirusTotal: ${threat.name || 'Threat detected'}`
                      }))
                    });
                    return;
                  }
                }
              }
              resolve({ success: true, threats: [] });
            } catch (e) {
              resolve({ success: false, threats: [] });
            }
          } else {
            resolve({ success: false, threats: [] });
          }
        });
      });
    } catch (error) {
      return { success: false, threats: [] };
    }
  }

  calculateSecurityRisk(threats, vulnerabilities) {
    const criticalThreats = threats.filter(t => t.severity === 'critical').length;
    const highThreats = threats.filter(t => t.severity === 'high').length;
    const mediumThreats = threats.filter(t => t.severity === 'medium').length;
    const highVulns = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumVulns = vulnerabilities.filter(v => v.severity === 'medium').length;

    if (criticalThreats > 0) return 'critical';
    if (highThreats > 0 || highVulns > 0) return 'high';
    if (mediumThreats > 1 || mediumVulns > 1) return 'medium';
    return 'low';
  }

  generateSecurityRecommendations(security) {
    const recommendations = [];

    if (security.riskLevel === 'critical') {
      recommendations.push('Archivo crítico detectado - Eliminar inmediatamente');
      recommendations.push('Ejecutar escaneo completo del sistema');
      recommendations.push('Verificar integridad del sistema');
    } else if (security.riskLevel === 'high') {
      recommendations.push('Revisar inmediatamente este archivo');
      recommendations.push('Considerar cuarentena del archivo');
    }

    if (security.threats.some(t => t.type === 'executable_file')) {
      recommendations.push('Verificar la fuente del archivo ejecutable');
      recommendations.push('Ejecutar escaneo antivirus adicional');
    }

    if (security.threats.some(t => t.type === 'eicar_test_file')) {
      recommendations.push('Archivo de prueba EICAR - Completamente seguro');
      recommendations.push('Este archivo es usado para probar antivirus');
    }

    if (security.threats.some(t => t.type === 'virustotal_detection')) {
      recommendations.push('Threat detectado por VirusTotal');
      recommendations.push('Considerar eliminar el archivo');
    }

    if (security.vulnerabilities.some(v => v.type === 'permissive_permissions')) {
      recommendations.push('Restringir permisos del archivo');
    }

    return recommendations;
  }

  getFileType(extension) {
    const typeMap = {
      '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image',
      '.pdf': 'document', '.doc': 'document', '.docx': 'document', '.txt': 'text',
      '.zip': 'archive', '.rar': 'archive', '.7z': 'archive',
      '.exe': 'executable', '.msi': 'executable', '.dll': 'executable',
      '.js': 'script', '.py': 'script', '.bat': 'script'
    };
    
    return typeMap[extension.toLowerCase()] || 'unknown';
  }

  isExecutable(filePath) {
    const executableExtensions = ['.exe', '.msi', '.bat', '.cmd', '.scr', '.pif', '.com'];
    return executableExtensions.includes(path.extname(filePath).toLowerCase());
  }

  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  getAnalysisHistory() {
    return this.analysisHistory;
  }

  clearAnalysisHistory() {
    this.analysisHistory = [];
    return { success: true, message: 'Historial de análisis limpiado' };
  }
}

module.exports = FileAnalyzer;
