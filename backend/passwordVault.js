const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Configuración de la bóveda de contraseñas
const VAULT_CONFIG = {
  vaultDir: path.join(__dirname, 'vault'),
  vaultFile: 'passwords.txt',
  encryptionKey: 'ciberseg-vault-key-2024', // En producción, esto debería ser más seguro
  salt: 'ciberseg-salt-2024'
};

// Crear directorio de bóveda si no existe
function ensureVaultDirectory() {
  if (!fs.existsSync(VAULT_CONFIG.vaultDir)) {
    fs.mkdirSync(VAULT_CONFIG.vaultDir, { recursive: true });
  }
}

// Función de cifrado usando métodos modernos
function encrypt(text) {
  try {
    // Crear un hash del key para obtener una clave de 32 bytes
    const key = crypto.createHash('sha256').update(VAULT_CONFIG.encryptionKey).digest();
    // Crear un IV aleatorio
    const iv = crypto.randomBytes(16);
    // Crear el cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    // Cifrar el texto
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    // Combinar IV y texto cifrado
    return iv.toString('hex') + ':' + encrypted;
  } catch (error) {
    console.error('Error cifrando datos:', error);
    return null;
  }
}

// Función de descifrado usando métodos modernos
function decrypt(encryptedText) {
  try {
    // Separar IV y texto cifrado
    const parts = encryptedText.split(':');
    if (parts.length !== 2) {
      throw new Error('Formato de datos cifrados inválido');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    
    // Crear un hash del key para obtener una clave de 32 bytes
    const key = crypto.createHash('sha256').update(VAULT_CONFIG.encryptionKey).digest();
    // Crear el decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    // Descifrar el texto
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('Error descifrando datos:', error);
    return null;
  }
}

// Leer contraseñas de la bóveda
function readPasswordVault() {
  try {
    ensureVaultDirectory();
    const vaultPath = path.join(VAULT_CONFIG.vaultDir, VAULT_CONFIG.vaultFile);
    
    if (!fs.existsSync(vaultPath)) {
      return [];
    }
    
    const encryptedData = fs.readFileSync(vaultPath, 'utf8');
    
    // Intentar descifrar con el nuevo método
    let decryptedData = decrypt(encryptedData);
    
    // Si falla, intentar con el método anterior (para migración)
    if (!decryptedData) {
      console.log('Intentando migrar datos del formato anterior...');
      try {
        const decipher = crypto.createDecipher('aes192', VAULT_CONFIG.encryptionKey);
        let oldDecrypted = decipher.update(encryptedData, 'hex', 'utf8');
        oldDecrypted += decipher.final('utf8');
        decryptedData = oldDecrypted;
        
        // Migrar a nuevo formato
        const passwords = JSON.parse(decryptedData);
        writePasswordVault(passwords);
        console.log('Datos migrados exitosamente al nuevo formato');
      } catch (migrationError) {
        console.error('Error en migración:', migrationError);
        return [];
      }
    }
    
    if (!decryptedData) {
      console.error('No se pudieron descifrar los datos de la bóveda');
      return [];
    }
    
    return JSON.parse(decryptedData);
  } catch (error) {
    console.error('Error leyendo bóveda de contraseñas:', error);
    return [];
  }
}

// Escribir contraseñas a la bóveda
function writePasswordVault(passwords) {
  try {
    ensureVaultDirectory();
    const vaultPath = path.join(VAULT_CONFIG.vaultDir, VAULT_CONFIG.vaultFile);
    
    const jsonData = JSON.stringify(passwords, null, 2);
    const encryptedData = encrypt(jsonData);
    
    if (!encryptedData) {
      console.error('Error: No se pudo cifrar los datos');
      return false;
    }
    
    fs.writeFileSync(vaultPath, encryptedData, 'utf8');
    return true;
  } catch (error) {
    console.error('Error escribiendo bóveda de contraseñas:', error);
    return false;
  }
}

// Agregar contraseña a la bóveda
function addPasswordToVault(label, password, username = '', website = '', notes = '') {
  try {
    const passwords = readPasswordVault();
    
    // Verificar si ya existe una contraseña con el mismo label
    const existingIndex = passwords.findIndex(p => p.label === label);
    
    const passwordEntry = {
      id: Date.now().toString(),
      label,
      password,
      username,
      website,
      notes,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      strength: calculatePasswordStrength(password)
    };
    
    if (existingIndex >= 0) {
      // Actualizar contraseña existente
      passwords[existingIndex] = passwordEntry;
    } else {
      // Agregar nueva contraseña
      passwords.push(passwordEntry);
    }
    
    const success = writePasswordVault(passwords);
    return {
      success,
      message: existingIndex >= 0 ? 'Contraseña actualizada' : 'Contraseña agregada',
      password: passwordEntry
    };
  } catch (error) {
    console.error('Error agregando contraseña:', error);
    return {
      success: false,
      message: 'Error agregando contraseña',
      error: error.message
    };
  }
}

// Eliminar contraseña de la bóveda
function removePasswordFromVault(passwordId) {
  try {
    const passwords = readPasswordVault();
    const filteredPasswords = passwords.filter(p => p.id !== passwordId);
    
    if (filteredPasswords.length === passwords.length) {
      return {
        success: false,
        message: 'Contraseña no encontrada'
      };
    }
    
    const success = writePasswordVault(filteredPasswords);
    return {
      success,
      message: 'Contraseña eliminada'
    };
  } catch (error) {
    console.error('Error eliminando contraseña:', error);
    return {
      success: false,
      message: 'Error eliminando contraseña',
      error: error.message
    };
  }
}

// Obtener todas las contraseñas
function getAllPasswords() {
  try {
    const passwords = readPasswordVault();
    return {
      success: true,
      passwords,
      count: passwords.length
    };
  } catch (error) {
    console.error('Error obteniendo contraseñas:', error);
    return {
      success: false,
      passwords: [],
      count: 0,
      error: error.message
    };
  }
}

// Buscar contraseñas
function searchPasswords(query) {
  try {
    const passwords = readPasswordVault();
    const filtered = passwords.filter(p => 
      p.label.toLowerCase().includes(query.toLowerCase()) ||
      p.username.toLowerCase().includes(query.toLowerCase()) ||
      p.website.toLowerCase().includes(query.toLowerCase()) ||
      p.notes.toLowerCase().includes(query.toLowerCase())
    );
    
    return {
      success: true,
      passwords: filtered,
      count: filtered.length
    };
  } catch (error) {
    console.error('Error buscando contraseñas:', error);
    return {
      success: false,
      passwords: [],
      count: 0,
      error: error.message
    };
  }
}

// Exportar bóveda
function exportVault(format = 'json') {
  try {
    const passwords = readPasswordVault();
    const exportData = {
      vault: passwords,
      exportDate: new Date().toISOString(),
      totalPasswords: passwords.length,
      version: '1.0',
      application: 'CiberSeg'
    };
    
    if (format === 'json') {
      return {
        success: true,
        data: JSON.stringify(exportData, null, 2),
        format: 'json',
        filename: `password-vault-${new Date().toISOString().split('T')[0]}.json`
      };
    } else if (format === 'csv') {
      const csvData = [
        'Label,Username,Password,Website,Notes,CreatedAt,Strength',
        ...passwords.map(p => 
          `"${p.label}","${p.username}","${p.password}","${p.website}","${p.notes}","${p.createdAt}","${p.strength}"`
        )
      ].join('\n');
      
      return {
        success: true,
        data: csvData,
        format: 'csv',
        filename: `password-vault-${new Date().toISOString().split('T')[0]}.csv`
      };
    } else {
      return {
        success: false,
        message: 'Formato no soportado'
      };
    }
  } catch (error) {
    console.error('Error exportando bóveda:', error);
    return {
      success: false,
      message: 'Error exportando bóveda',
      error: error.message
    };
  }
}

// Importar bóveda
function importVault(importData) {
  try {
    const data = JSON.parse(importData);
    
    if (!data.vault || !Array.isArray(data.vault)) {
      return {
        success: false,
        message: 'Formato de archivo inválido'
      };
    }
    
    const existingPasswords = readPasswordVault();
    const importedPasswords = data.vault.map(p => ({
      ...p,
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      createdAt: p.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      strength: calculatePasswordStrength(p.password)
    }));
    
    const mergedPasswords = [...existingPasswords, ...importedPasswords];
    const success = writePasswordVault(mergedPasswords);
    
    return {
      success,
      message: `Importadas ${importedPasswords.length} contraseñas`,
      importedCount: importedPasswords.length
    };
  } catch (error) {
    console.error('Error importando bóveda:', error);
    return {
      success: false,
      message: 'Error importando bóveda',
      error: error.message
    };
  }
}

// Recalculate password strengths for all existing passwords
function recalculateAllPasswordStrengths() {
  try {
    const passwords = readPasswordVault();
    let updated = false;
    
    passwords.forEach(password => {
      const newStrength = calculatePasswordStrength(password.password);
      if (password.strength !== newStrength) {
        password.strength = newStrength;
        password.updatedAt = new Date().toISOString();
        updated = true;
      }
    });
    
    if (updated) {
      const success = writePasswordVault(passwords);
      return {
        success,
        message: 'Fortalezas de contraseñas recalculadas',
        updatedCount: passwords.length
      };
    } else {
      return {
        success: true,
        message: 'No se necesitaron actualizaciones',
        updatedCount: 0
      };
    }
  } catch (error) {
    console.error('Error recalculando fortalezas:', error);
    return {
      success: false,
      message: 'Error recalculando fortalezas',
      error: error.message
    };
  }
}

// Calcular fortaleza de contraseña
function calculatePasswordStrength(password) {
  let score = 0;
  
  // Length scoring (more generous for longer passwords)
  if (password.length >= 32) score += 40;
  else if (password.length >= 24) score += 35;
  else if (password.length >= 16) score += 30;
  else if (password.length >= 12) score += 25;
  else if (password.length >= 8) score += 15;
  else if (password.length >= 6) score += 10;
  else if (password.length >= 4) score += 5;
  
  // Character variety scoring
  if (/[a-z]/.test(password)) score += 8;
  if (/[A-Z]/.test(password)) score += 8;
  if (/[0-9]/.test(password)) score += 8;
  if (/[^A-Za-z0-9]/.test(password)) score += 12;
  
  // Bonus for multiple character types
  const charTypes = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /[0-9]/.test(password),
    /[^A-Za-z0-9]/.test(password)
  ].filter(Boolean).length;
  
  if (charTypes >= 4) score += 15;
  else if (charTypes >= 3) score += 10;
  else if (charTypes >= 2) score += 5;
  
  // Penalties for patterns
  if (/(.)\1{2,}/.test(password)) score -= 15; // Repeated characters
  if (/123|abc|qwe|password|admin/i.test(password)) score -= 20; // Common patterns
  if (password.length > 0 && password.length < 8) score -= 10; // Too short
  
  // Ensure score is within bounds
  return Math.max(0, Math.min(100, score));
}

// Obtener estadísticas de la bóveda
function getVaultStats() {
  try {
    const passwords = readPasswordVault();
    
    let strongCount = 0;
    let mediumCount = 0;
    let weakCount = 0;
    let lastAdded = null;
    
    passwords.forEach(p => {
      if (p.strength >= 80) {
        strongCount++;
      } else if (p.strength >= 50) {
        mediumCount++;
      } else {
        weakCount++;
      }
      
      // Track the most recent password
      if (!lastAdded || new Date(p.createdAt) > new Date(lastAdded)) {
        lastAdded = p.createdAt;
      }
    });
    
    return {
      success: true,
      stats: {
        totalPasswords: passwords.length,
        strongPasswords: strongCount,
        mediumPasswords: mediumCount,
        weakPasswords: weakCount,
        averageStrength: passwords.length > 0 ? 
          Math.round(passwords.reduce((sum, p) => sum + p.strength, 0) / passwords.length) : 0,
        lastAdded: lastAdded
      }
    };
  } catch (error) {
    console.error('Error obteniendo estadísticas:', error);
    return {
      success: false,
      stats: null,
      error: error.message
    };
  }
}

module.exports = {
  addPasswordToVault,
  removePasswordFromVault,
  getAllPasswords,
  searchPasswords,
  exportVault,
  importVault,
  getVaultStats,
  calculatePasswordStrength,
  recalculateAllPasswordStrengths
};
