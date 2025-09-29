// Modern JavaScript para la aplicación CiberSeg
class CiberSegApp {
  constructor() {
    this.currentSection = 'dashboard';
    this.termsAccepted = this.checkTermsAcceptance();
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.setupAnimations();
    this.loadDashboardData();
    this.initializeKeylogger();
    this.initializeAntivirusStats();
    this.loadAppData();
    
    // Siempre mostrar modal de términos para propósitos de prueba
    this.showTermsModal();
    
    // Mostrar modal de términos si no se ha aceptado (descomentar cuando termine la prueba)
    // if (!this.termsAccepted) {
    //   this.showTermsModal();
    // }
    
    console.log('Aplicación CiberSeg inicializada exitosamente');
  }

  setupEventListeners() {
    // Menú de navegación
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        const section = e.currentTarget.dataset.section;
        this.navigateToSection(section);
      });
    });

  // Acciones rápidas (banner puede estar ausente) - sin operación si elementos no están presentes
  const quickScanBtn = document.getElementById('quick-scan');
  if (quickScanBtn) quickScanBtn.addEventListener('click', (e) => { e.stopPropagation(); this.startVulnerabilityScan(); });

  const openPasswordsBtn = document.getElementById('open-passwords');
  if (openPasswordsBtn) openPasswordsBtn.addEventListener('click', (e) => { e.stopPropagation(); this.navigateToSection('passwords'); });

    // Tarjetas de módulos
    const moduleCards = document.querySelectorAll('.module-card[data-module]');
    moduleCards.forEach(card => {
      card.addEventListener('click', (e) => {
        const module = e.currentTarget.dataset.module;
        this.openModule(module);
      });
    });


    // Alternar menú móvil
    const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
    if (mobileMenuToggle) {
      mobileMenuToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        this.toggleMobileMenu();
      });
    }

    // Botones de acción dentro de los módulos
    document.querySelectorAll('[data-action]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = btn.dataset.action;
        this.handleAction(action, btn);
      });
    });

    // Funcionalidad de búsqueda
    const searchInput = document.querySelector('.search-container input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.handleSearch(e.target.value);
      });
    }

    // Interacciones de botones
    this.setupButtonInteractions();

    // Cerrar el menú móvil cuando se hace clic fuera
    document.addEventListener('click', (e) => {
      const sidebar = document.getElementById('app-sidebar');
      const mobileToggle = document.getElementById('mobile-menu-toggle');
      
      if (sidebar && sidebar.classList.contains('open') && 
          !sidebar.contains(e.target) && 
          !mobileToggle.contains(e.target)) {
        sidebar.classList.remove('open');
      }
    });

    // Escuchadores de eventos del modal de términos
    const acceptTermsBtn = document.getElementById('accept-terms');
    const declineTermsBtn = document.getElementById('decline-terms');
    
    if (acceptTermsBtn) {
      acceptTermsBtn.addEventListener('click', () => this.acceptTerms());
    }
    
    if (declineTermsBtn) {
      declineTermsBtn.addEventListener('click', () => this.declineTerms());
    }

    // Deslizador de longitud de contraseña
    const passwordLengthSlider = document.getElementById('password-length');
    const lengthValueDisplay = document.getElementById('length-value');
    
    if (passwordLengthSlider && lengthValueDisplay) {
      passwordLengthSlider.addEventListener('input', (e) => {
        lengthValueDisplay.textContent = e.target.value;
      });
    }

    // Interacciones de casillas personalizadas
    const checkboxes = document.querySelectorAll('.checkbox-toggle');
    checkboxes.forEach(checkbox => {
      const input = document.getElementById(checkbox.dataset.checkbox);
      if (input) {
        // Establecer estado inicial
        if (input.checked) {
          checkbox.classList.add('checked');
        }
        
        // Manejar clic en casilla personalizada
        checkbox.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          input.checked = !input.checked;
          if (input.checked) {
            checkbox.classList.add('checked');
          } else {
            checkbox.classList.remove('checked');
          }
        });
        
        // Manejar clic en etiqueta
        const label = checkbox.closest('label');
        if (label) {
          label.addEventListener('click', (e) => {
            e.preventDefault();
            input.checked = !input.checked;
            if (input.checked) {
              checkbox.classList.add('checked');
            } else {
              checkbox.classList.remove('checked');
            }
          });
        }
      }
    });

    // Event listeners para botones de gestión de logs forenses
    const forensicsClearBtn = document.getElementById('forensics-clear-log-btn');
    const forensicsExportBtn = document.getElementById('forensics-export-btn');
    
    if (forensicsClearBtn) {
      forensicsClearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.clearForensicsLog();
      });
    }
    
    if (forensicsExportBtn) {
      forensicsExportBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.exportForensicsResults();
      });
    }
    

    // Antivirus progress updates
    if (window.electronAPI && window.electronAPI.onAntivirusProgress) {
      window.electronAPI.onAntivirusProgress((event, progressData) => {
        this.handleAntivirusProgress(progressData);
      });
    }
  }

  setupButtonInteractions() {
    // Eliminar escuchadores duplicados - botones con data-action se manejan en otro lugar
    const buttons = document.querySelectorAll('.btn-primary:not([data-action])');
    buttons.forEach(button => {
      button.addEventListener('click', (e) => {
        e.stopPropagation();
        this.handleButtonClick(button);
      });
    });

    // Navegación de la barra lateral: asegurar que los elementos de navegación con no data-section no fallen
    document.querySelectorAll('.nav-item').forEach(item => {
      if (!item.dataset.section) item.dataset.section = 'dashboard';
      // Accesibilidad: activar con Enter/Espacio
      item.setAttribute('tabindex', '0');
      item.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          const section = item.dataset.section;
          this.navigateToSection(section);
        }
      });
    });
  }


  toggleMobileMenu() {
    const sidebar = document.getElementById('app-sidebar');
    if (!sidebar) return;
    
    const isOpen = sidebar.classList.contains('open');
    if (isOpen) {
      sidebar.classList.remove('open');
    } else {
      sidebar.classList.add('open');
    }
  }

  handleAction(action, el) {
    switch (action) {
      case 'open-passwords':
        this.navigateToSection('passwords');
        break;
      case 'open-forensics':
        this.navigateToSection('forensics');
        break;
      case 'generate-password':
        this.generateNewPassword();
        break;
      case 'start-simulation':
        this.startSimulation();
        break;
      case 'config-simulation':
        this.navigateToSection('simulation');
        this.showNotification('Configuración de simulación abierta', 'info');
        break;
      case 'run-analysis':
        this.openForensicAnalysis();
        break;
      case 'open-tools':
        this.navigateToSection('settings');
        break;
      // Antivirus actions
      case 'start-antivirus-scan':
        this.startAntivirusScan();
        break;
      case 'stop-antivirus-scan':
        this.stopAntivirusScan();
        break;
      case 'scan-file':
        this.scanFile();
        break;
      case 'antivirus-settings':
        this.openAntivirusSettings();
        break;
      // File Analyzer actions
      case 'analyze-file':
        this.analyzeFile();
        break;
      case 'view-analysis-reports':
        this.viewAnalysisReports();
        break;
      // System Analysis actions
      case 'full-system-analysis':
        this.fullSystemAnalysis();
        break;
      case 'system-report':
        this.generateSystemReport();
        break;
      // Antivirus Testing actions
      case 'generate-test-files':
        this.generateTestFiles();
        break;
      case 'test-eicar-detection':
        this.testEicarDetection();
        break;
      case 'generate-advanced-test-files':
        this.generateAdvancedTestFiles();
        break;
      case 'generate-aggressive-test-files':
        this.generateAggressiveTestFiles();
        break;
      case 'test-real-antivirus-detection':
        this.testRealAntivirusDetection();
        break;
      case 'diagnose-antivirus-status':
        this.diagnoseAntivirusStatus();
        break;
      case 'generate-real-malware-tests':
        this.generateRealMalwareTests();
        break;
      case 'comprehensive-antivirus-diagnostic':
        this.comprehensiveAntivirusDiagnostic();
        break;
      case 'delete-threats':
        this.deleteThreats();
        break;
      case 'clear-threat-history':
        this.clearThreatHistory();
        break;
      // Forensics log management
      case 'forensics-clear-log':
        this.clearForensicsLog();
        break;
      case 'forensics-export':
        this.exportForensicsResults();
        break;
      case 'forensics-settings':
        this.openForensicsSettings();
        break;
      // Acciones simplificadas del módulo de contraseñas
      case 'copy-password':
        this.copyPassword();
        break;
      case 'save-password':
        this.saveGeneratedPassword();
        break;
      case 'view-vault':
        this.viewVault();
        break;
      case 'add-to-vault':
        this.addToVault();
        break;
      case 'apply-settings':
        this.applyPasswordSettings();
        break;
      case 'export-vault':
        this.exportVault();
        break;
      case 'import-vault':
        this.importVault();
        break;
      case 'vault-settings':
        this.openVaultSettings();
        break;
      default:
        this.showNotification(`Acción: ${action}`, 'info');
    }
  }

  navigateToSection(section) {
    console.log(`Navegando a la sección: ${section}`);
    
    // Actualizar navegación con clases coherentes
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    const targetNav = document.querySelector(`[data-section="${section}"]`);
    if (targetNav) targetNav.classList.add('active');

    // Ocultar TODAS las secciones de contenido primero - incluyendo el dashboard
    const allSections = document.querySelectorAll('.content-section');
    console.log(`Encontradas ${allSections.length} secciones para ocultar`);
    allSections.forEach(sec => {
      sec.classList.add('hidden');
      sec.classList.remove('active');
      sec.style.display = 'none';
      console.log(`Ocultando sección: ${sec.id}`);
    });

    // Mostrar SOLO la sección objetivo
    const targetSection = document.getElementById(`${section}-section`);
    if (targetSection) {
      targetSection.classList.remove('hidden');
      targetSection.classList.add('active');
      targetSection.style.display = 'block';
      console.log(`Mostrando sección: ${targetSection.id}`);
    } else {
      console.error(`Sección objetivo no encontrada: ${section}-section`);
    }

    // Actualizar el título de la página
    this.updatePageTitle(section);

    // Actualizar la sección actual
    this.currentSection = section;

    // Añadir animación de navegación
    this.animateSectionTransition();
  }

  updatePageTitle(section) {
    const titles = {
      dashboard: 'Dashboard',
      passwords: 'Gestión de Contraseñas',
      simulation: 'Simulación de Entorno',
      forensics: 'Herramientas Forenses',
      settings: 'Configuración'
    };

    const subtitles = {
      dashboard: 'Centro de herramientas de ciberseguridad',
      passwords: 'Administra y genera contraseñas seguras',
      simulation: 'Crea y ejecuta entornos virtuales controlados',
      forensics: 'Herramientas de análisis forense digital',
      settings: 'Configuración del sistema y preferencias'
    };

    const titleEl = document.getElementById('page-title');
    const subtitleEl = document.getElementById('page-subtitle');
    if (titleEl) titleEl.textContent = titles[section] || '';
    if (subtitleEl) subtitleEl.textContent = subtitles[section] || '';
  }

  animateSectionTransition() {
    const activeSection = document.querySelector('.content-section.active');
    if (!activeSection) return;
    activeSection.classList.add('opacity-0', 'translate-y-5');
    setTimeout(() => {
      activeSection.classList.add('transition-all', 'duration-300', 'ease-out');
      activeSection.classList.remove('opacity-0', 'translate-y-5');
      activeSection.classList.add('opacity-100', 'translate-y-0');
    }, 10);
  }

  openModule(module) {
    console.log(`Abriendo módulo: ${module}`);
    
    // Añadir estado de carga
    const moduleCard = document.querySelector(`[data-module="${module}"]`);
    if (!moduleCard) return;
    const button = moduleCard.querySelector('button');
    if (!button) return;
    const originalText = button.innerHTML;
    
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cargando...';
    button.disabled = true;

    // Manejar diferentes módulos
    setTimeout(() => {
      button.innerHTML = originalText;
      button.disabled = false;
      
          // Navegar a la sección adecuada basada en el módulo
      switch(module) {
        case 'passwords':
          this.navigateToSection('passwords');
          this.showNotification('Gestión de Contraseñas iniciada', 'success');
          break;
        case 'simulation':
          this.startSimulation();
          break;
        case 'forensics':
          this.navigateToSection('forensics');
          this.showNotification('Herramientas Forenses iniciadas', 'success');
          break;
        case 'coming-soon':
          this.showNotification('Este módulo estará disponible próximamente', 'info');
          break;
        default:
          this.navigateToSection(module);
          this.showNotification(`Módulo ${module} iniciado correctamente`, 'success');
      }
    }, 500);
  }

  handleButtonClick(button) {
    const buttonText = button.textContent.trim();
    
    // Añadir animación de clic
    button.style.transform = 'scale(0.95)';
    setTimeout(() => {
      button.style.transform = '';
    }, 150);

    // Manejar diferentes acciones de botones
    if (buttonText.includes('Nueva Contraseña')) {
      this.generateNewPassword();
    } else if (buttonText.includes('Abrir Análisis')) {
      this.openForensicAnalysis();
    } else if (buttonText.includes('Iniciar Simulación')) {
      this.startSimulation();
    }
  }


  async generateNewPassword() {
    try {
      // Obtener configuración actual
      const length = parseInt(document.getElementById('password-length')?.value || 16);
      const includeUppercase = document.getElementById('include-uppercase')?.checked || true;
      const includeLowercase = document.getElementById('include-lowercase')?.checked || true;
      const includeNumbers = document.getElementById('include-numbers')?.checked || true;
      const includeSymbols = document.getElementById('include-symbols')?.checked || true;

      // Generar contraseña basada en configuración
      let charset = '';
      if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
      if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      if (includeNumbers) charset += '0123456789';
      if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

      if (charset === '') {
        this.showNotification('Debe seleccionar al menos un tipo de carácter', 'warning');
        return;
      }

      let password = '';
      // Usar crypto.getRandomValues si está disponible para mejor aleatoriedad
      if (window.crypto && window.crypto.getRandomValues) {
        const array = new Uint32Array(length);
        window.crypto.getRandomValues(array);
        for (let i = 0; i < length; i++) {
          password += charset.charAt(array[i] % charset.length);
        }
      } else {
        // Respaldo a Math.random
        for (let i = 0; i < length; i++) {
          password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
      }

      // Actualizar pantalla
      const passwordElement = document.getElementById('last-generated-password');
      if (passwordElement) {
        passwordElement.textContent = password;
      }

      // Actualizar pantalla de contraseña del dashboard
      const dashboardPasswordDisplay = document.getElementById('dashboard-generated-password');
      if (dashboardPasswordDisplay) {
        dashboardPasswordDisplay.textContent = password;
      }

      // Habilitar botón de guardar
      const saveButton = document.querySelector('[data-action="save-password"]');
      if (saveButton) {
        saveButton.disabled = false;
        saveButton.classList.remove('opacity-50', 'cursor-not-allowed');
      }

      // Almacenar la contraseña actual para guardar
      this.currentGeneratedPassword = password;

      // Actualizar contraseñas recientes
      this.updateRecentPasswords(password);

      this.showNotification(`Nueva contraseña generada (${length} caracteres)`, 'success');
    } catch (error) {
      console.error('Error al generar contraseña:', error);
      this.showNotification('Error al generar contraseña', 'error');
    }
  }

  saveGeneratedPassword() {
    if (!this.currentGeneratedPassword) {
      this.showNotification('No hay contraseña generada para guardar', 'warning');
      return;
    }

    // Solicitar etiqueta/sitio web
    const label = prompt('¿Para qué sitio o servicio es esta contraseña?', '');
    if (!label || label.trim() === '') {
      this.showNotification('Debe especificar un nombre para la contraseña', 'warning');
      return;
    }

    // Guardar en bóveda
    const vaultItem = {
      label: label.trim(),
      password: this.currentGeneratedPassword,
      createdAt: new Date().toISOString(),
      strength: this.calculatePasswordStrength(this.currentGeneratedPassword)
    };

    const stored = JSON.parse(localStorage.getItem('password-vault') || '[]');
    stored.push(vaultItem);
    localStorage.setItem('password-vault', JSON.stringify(stored));

    // Actualizar información de bóveda
    localStorage.setItem('last-vault-activity', new Date().toISOString());
    this.loadVaultCount();
    this.loadPasswordList();

    // Deshabilitar botón de guardar
    const saveButton = document.querySelector('[data-action="save-password"]');
    if (saveButton) {
      saveButton.disabled = true;
      saveButton.classList.add('opacity-50', 'cursor-not-allowed');
    }

    this.showNotification(`Contraseña guardada para "${label}"`, 'success');
  }

  updateRecentPasswords(newPassword) {
    // Obtener contraseñas recientes existentes de localStorage
    let recentPasswords = JSON.parse(localStorage.getItem('recent-passwords') || '[]');
    
    // Verificar si la nueva contraseña ya está en la lista (prevenir duplicados)
    if (recentPasswords.includes(newPassword)) {
      return;
    }
    
    // Agregar nueva contraseña al principio
    recentPasswords.unshift(newPassword);
    
    // Mantener solo las últimas 3 contraseñas
    recentPasswords = recentPasswords.slice(0, 3);
    
    // Guardar de vuelta en localStorage
    localStorage.setItem('recent-passwords', JSON.stringify(recentPasswords));
    
    // Actualizar la pantalla
    const recentContainer = document.getElementById('recent-passwords');
    if (recentContainer) {
      recentContainer.innerHTML = '';
      
      recentPasswords.forEach((password, index) => {
        const passwordDiv = document.createElement('div');
        passwordDiv.className = 'text-xs font-mono bg-blue-50 px-2 py-1 rounded border border-blue-200 text-blue-800 cursor-pointer hover:bg-blue-100 transition-colors duration-200';
        passwordDiv.textContent = password;
        passwordDiv.title = 'Click para copiar';
        passwordDiv.addEventListener('click', () => {
          navigator.clipboard.writeText(password).then(() => {
            this.showNotification('Contraseña copiada', 'success');
          }).catch(() => {
            this.showNotification('Error al copiar', 'error');
          });
        });
        recentContainer.appendChild(passwordDiv);
      });
      
      // Llenar espacios restantes con marcador de posición si es necesario
      while (recentContainer.children.length < 3) {
        const placeholderDiv = document.createElement('div');
        placeholderDiv.className = 'text-xs font-mono bg-gray-50 px-2 py-1 rounded border text-gray-600 opacity-50';
        placeholderDiv.textContent = 'No hay contraseñas generadas';
        recentContainer.appendChild(placeholderDiv);
      }
    }
  }

  loadRecentPasswords() {
    const recentPasswords = JSON.parse(localStorage.getItem('recent-passwords') || '[]');
    const recentContainer = document.getElementById('recent-passwords');
    
    if (recentContainer && recentPasswords.length > 0) {
      recentContainer.innerHTML = '';
      
      recentPasswords.forEach((password) => {
        const passwordDiv = document.createElement('div');
        passwordDiv.className = 'text-xs font-mono bg-blue-50 px-2 py-1 rounded border border-blue-200 text-blue-800 cursor-pointer hover:bg-blue-100 transition-colors duration-200';
        passwordDiv.textContent = password;
        passwordDiv.title = 'Click para copiar';
        passwordDiv.addEventListener('click', () => {
          navigator.clipboard.writeText(password).then(() => {
            this.showNotification('Contraseña copiada', 'success');
          }).catch(() => {
            this.showNotification('Error al copiar', 'error');
          });
        });
        recentContainer.appendChild(passwordDiv);
      });
      
      // Llenar espacios restantes con marcador de posición si es necesario
      while (recentContainer.children.length < 3) {
        const placeholderDiv = document.createElement('div');
        placeholderDiv.className = 'text-xs font-mono bg-gray-50 px-2 py-1 rounded border text-gray-600 opacity-50';
        placeholderDiv.textContent = 'No hay contraseñas generadas';
        recentContainer.appendChild(placeholderDiv);
      }
    }
  }

  generateSecurePassword() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < 16; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }


  async openForensicAnalysis() {
    this.showNotification('Abriendo herramientas forenses...', 'info');
    
    try {
      // Para fines de demostración, analizar un archivo de muestra
      const result = await window.electronAPI.forensicAnalysis('sample-file.exe');
      
      if (result.status === 'completado') {
        this.showNotification(`Análisis completado. Archivo: ${result.fileType}, Sospechoso: ${result.suspicious ? 'Sí' : 'No'}`, 'success');
        console.log('Resultado del análisis forense:', result);
      }
    } catch (error) {
      console.error('Error en el análisis forense:', error);
      this.showNotification('Error en el análisis forense', 'error');
    }
  }

  startSimulation() {
    this.showNotification('Simulación iniciada. Preparando entorno...', 'info');
    setTimeout(() => this.showNotification('Simulación corriendo en modo controlado', 'success'), 1200);
  }

  handleSearch(query) {
    if (!query || query.length < 2) return;
    // Implementación de búsqueda simple: resaltar módulos con texto coincidente
    const modules = document.querySelectorAll('.module-card');
    modules.forEach(m => {
      const text = m.innerText.toLowerCase();
      if (text.includes(query.toLowerCase())) {
        m.style.boxShadow = '0 8px 22px rgba(37,99,235,0.08)';
      } else {
        m.style.boxShadow = '';
      }
    });
  }

  setupAnimations() {
    // Revelación en cascada para las tarjetas de módulos y elevación de hover
    const grid = document.querySelector('.modules-grid');
    if (!grid) return;
    const cards = Array.from(grid.querySelectorAll('.bg-white, .module-card'));

    cards.forEach((card, i) => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(12px)';
      card.style.transition = 'all 420ms cubic-bezier(.2,.9,.2,1)';
      setTimeout(() => {
        card.style.opacity = '1';
        card.style.transform = 'translateY(0)';
      }, 80 * i + 80);

      // Elevación de hover
      card.addEventListener('mouseenter', () => {
        card.style.transform = 'translateY(-6px) scale(1.01)';
        card.style.boxShadow = '0 14px 34px rgba(2,6,23,0.12)';
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'translateY(0) scale(1)';
        card.style.boxShadow = '';
      });
    });
  }

  loadDashboardData() {
    // Placeholder para obtener datos reales desde el proceso principal via preload
    this.loadVaultCount();
    this.loadRecentPasswords();
    this.loadPasswordList();
  }

  loadVaultCount() {
    const stored = JSON.parse(localStorage.getItem('password-vault') || '[]');
    const counter = document.getElementById('stored-count');
    if (counter) {
      counter.textContent = stored.length;
    }
    
    // Actualizar estadísticas de fortaleza de contraseña
    this.updatePasswordStrengthStats(stored);
    
    // Actualizar actividad de bóveda e información de almacenamiento
    this.updateVaultInfo();
  }

  updatePasswordStrengthStats(passwords) {
    let strongCount = 0;
    let mediumCount = 0;
    let weakCount = 0;
    
    passwords.forEach(item => {
      const strength = this.calculatePasswordStrength(item.password);
      if (strength >= 80) {
        strongCount++;
      } else if (strength >= 50) {
        mediumCount++;
      } else {
        weakCount++;
      }
    });
    
    const strongEl = document.getElementById('strong-count');
    const mediumEl = document.getElementById('medium-count');
    const weakEl = document.getElementById('weak-count');
    
    if (strongEl) strongEl.textContent = strongCount;
    if (mediumEl) mediumEl.textContent = mediumCount;
    if (weakEl) weakEl.textContent = weakCount;
  }

  calculatePasswordStrength(password) {
    let score = 0;
    
    // Bonificación por longitud
    if (password.length >= 12) score += 25;
    else if (password.length >= 8) score += 15;
    else if (password.length >= 6) score += 10;
    
    // Variedad de caracteres
    if (/[a-z]/.test(password)) score += 5;
    if (/[A-Z]/.test(password)) score += 5;
    if (/[0-9]/.test(password)) score += 5;
    if (/[^A-Za-z0-9]/.test(password)) score += 10;
    
    // Penalizaciones por patrones
    if (/(.)\1{2,}/.test(password)) score -= 10; // Repeated characters
    if (/123|abc|qwe/i.test(password)) score -= 15; // Common patterns
    
    return Math.max(0, Math.min(100, score));
  }

  updateVaultInfo() {
    const stored = JSON.parse(localStorage.getItem('password-vault') || '[]');
    
    // Actualizar última actividad
    const lastActivity = localStorage.getItem('last-vault-activity');
    const lastActivityEl = document.getElementById('last-vault-activity');
    if (lastActivityEl) {
      if (lastActivity) {
        const date = new Date(lastActivity);
        lastActivityEl.textContent = date.toLocaleString();
      } else {
        lastActivityEl.textContent = 'Nunca';
      }
    }
    
    // Actualizar tamaño de almacenamiento
    const storageSize = JSON.stringify(stored).length;
    const storageEl = document.getElementById('vault-storage');
    if (storageEl) {
      if (storageSize < 1024) {
        storageEl.textContent = `${storageSize} B`;
      } else if (storageSize < 1024 * 1024) {
        storageEl.textContent = `${(storageSize / 1024).toFixed(1)} KB`;
      } else {
        storageEl.textContent = `${(storageSize / (1024 * 1024)).toFixed(1)} MB`;
      }
    }
  }

  loadPasswordList() {
    const stored = JSON.parse(localStorage.getItem('password-vault') || '[]');
    const passwordListEl = document.getElementById('password-list');
    const vaultSubtitleEl = document.getElementById('vault-subtitle');
    
    if (!passwordListEl) return;
    
    // Actualizar subtítulo
    if (vaultSubtitleEl) {
      vaultSubtitleEl.textContent = `(${Math.min(stored.length, 5)} de ${stored.length})`;
    }
    
    // Encontrar el contenedor interno para elementos de contraseña
    let innerContainer = passwordListEl.querySelector('.space-y-3');
    if (!innerContainer) {
      innerContainer = document.createElement('div');
      innerContainer.className = 'space-y-3';
      passwordListEl.appendChild(innerContainer);
    }
    
    // Limpiar lista existente
    innerContainer.innerHTML = '';
    
    // Mostrar primeras 5 contraseñas o marcador de posición si está vacío
    const passwordsToShow = stored.slice(0, 5);
    
    if (passwordsToShow.length === 0) {
      // Mostrar marcador de posición
      const placeholder = document.createElement('div');
      placeholder.className = 'text-center p-8 text-gray-500';
      placeholder.innerHTML = `
        <i class="fas fa-vault text-4xl mb-4 text-gray-300"></i>
        <p class="text-lg font-medium mb-2">No hay contraseñas guardadas</p>
        <p class="text-sm">Agrega tu primera contraseña para comenzar</p>
      `;
      innerContainer.appendChild(placeholder);
    } else {
      // Mostrar contraseñas
      passwordsToShow.forEach((item, index) => {
        const passwordItem = this.createPasswordItem(item, index);
        innerContainer.appendChild(passwordItem);
      });
    }
  }

  createPasswordItem(item, index) {
    const div = document.createElement('div');
    div.className = 'p-3 bg-gray-50 rounded-lg border border-gray-200 hover:bg-gray-100 transition-colors duration-200';
    
    // Obtener información del sitio web de la etiqueta o generar predeterminado
    const websiteInfo = this.getWebsiteInfo(item.label);
    
    div.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 ${websiteInfo.bgColor} rounded-lg flex items-center justify-center">
            <i class="${websiteInfo.icon} ${websiteInfo.textColor} text-sm"></i>
          </div>
          <div>
            <div class="font-medium text-gray-800">${websiteInfo.name}</div>
            <div class="text-sm text-gray-500">${websiteInfo.domain}</div>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <div class="text-xs font-mono bg-white px-2 py-1 rounded border">••••••••</div>
          <button class="p-1 text-gray-400 hover:text-gray-600 transition-colors" title="Copiar" data-copy-password="${index}">
            <i class="fas fa-copy text-sm"></i>
          </button>
        </div>
      </div>
    `;
    
    // Agregar funcionalidad de copia
    const copyBtn = div.querySelector(`[data-copy-password="${index}"]`);
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(item.password).then(() => {
          this.showNotification('Contraseña copiada', 'success');
        }).catch(() => {
          this.showNotification('Error al copiar', 'error');
        });
      });
    }
    
    return div;
  }

  getWebsiteInfo(label) {
    // Detección simple de sitio web basada en patrones comunes
    const websites = {
      'google': { name: 'Google', domain: 'google.com', icon: 'fas fa-globe', bgColor: 'bg-blue-100', textColor: 'text-blue-600' },
      'outlook': { name: 'Outlook', domain: 'outlook.com', icon: 'fas fa-envelope', bgColor: 'bg-green-100', textColor: 'text-green-600' },
      'amazon': { name: 'Amazon', domain: 'amazon.com', icon: 'fas fa-shopping-cart', bgColor: 'bg-purple-100', textColor: 'text-purple-600' },
      'netflix': { name: 'Netflix', domain: 'netflix.com', icon: 'fas fa-video', bgColor: 'bg-red-100', textColor: 'text-red-600' },
      'github': { name: 'GitHub', domain: 'github.com', icon: 'fas fa-code-branch', bgColor: 'bg-yellow-100', textColor: 'text-yellow-600' },
      'facebook': { name: 'Facebook', domain: 'facebook.com', icon: 'fab fa-facebook', bgColor: 'bg-blue-100', textColor: 'text-blue-600' },
      'twitter': { name: 'Twitter', domain: 'twitter.com', icon: 'fab fa-twitter', bgColor: 'bg-blue-100', textColor: 'text-blue-600' },
      'instagram': { name: 'Instagram', domain: 'instagram.com', icon: 'fab fa-instagram', bgColor: 'bg-pink-100', textColor: 'text-pink-600' }
    };
    
    const lowerLabel = label.toLowerCase();
    for (const [key, info] of Object.entries(websites)) {
      if (lowerLabel.includes(key)) {
        return info;
      }
    }
    
    // Respaldo predeterminado
    return {
      name: label,
      domain: 'website.com',
      icon: 'fas fa-globe',
      bgColor: 'bg-gray-100',
      textColor: 'text-gray-600'
    };
  }

  showNotification(message, type = 'info') {
    // Mecanismo de notificación
    const containerId = 'ciberseg-notifications';
    let container = document.getElementById(containerId);
    if (!container) {
      container = document.createElement('div');
      container.id = containerId;
      container.style.position = 'fixed';
      container.style.right = '20px';
      container.style.bottom = '20px';
      container.style.zIndex = 9999;
      container.style.display = 'flex';
      container.style.flexDirection = 'column';
      container.style.gap = '12px';
      document.body.appendChild(container);
    }

    const el = document.createElement('div');
    el.style.cssText = `
      background: ${this.getNotificationColor(type)};
      color: white;
      padding: 16px 20px;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.12);
      font-weight: 500;
      font-size: 14px;
      max-width: 400px;
      word-wrap: break-word;
      transform: translateX(100%);
      transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    `;

    // Añadir icono basado en el tipo
    const icon = this.getNotificationIcon(type);
    el.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px;">
        <i class="${icon}" style="font-size: 18px;"></i>
        <span>${message}</span>
      </div>
    `;

    container.appendChild(el);
    
    // Animación de entrada
    setTimeout(() => {
      el.style.transform = 'translateX(0)';
    }, 10);

    // Auto eliminar
    setTimeout(() => {
      el.style.transform = 'translateX(100%)';
      setTimeout(() => el.remove(), 300);
    }, 4000);
  }

  getNotificationColor(type) {
    const colors = {
      success: 'linear-gradient(135deg, #10b981, #059669)',
      warning: 'linear-gradient(135deg, #f59e0b, #d97706)',
      error: 'linear-gradient(135deg, #ef4444, #dc2626)',
      info: 'linear-gradient(135deg, #3b82f6, #2563eb)'
    };
    return colors[type] || colors.info;
  }

  getNotificationIcon(type) {
    const icons = {
      success: 'fas fa-check-circle',
      warning: 'fas fa-exclamation-triangle',
      error: 'fas fa-times-circle',
      info: 'fas fa-info-circle'
    };
    return icons[type] || icons.info;
  }

  // Métodos Simplificados del Módulo de Contraseñas
  copyPassword() {
    const passwordElement = document.getElementById('last-generated-password');
    if (passwordElement && passwordElement.textContent !== '********************') {
      navigator.clipboard.writeText(passwordElement.textContent).then(() => {
        this.showNotification('Contraseña copiada al portapapeles', 'success');
      }).catch(() => {
        this.showNotification('Error al copiar la contraseña', 'error');
      });
    } else {
      this.showNotification('No hay contraseña generada para copiar', 'warning');
    }
  }

  viewVault() {
    this.showNotification('Abriendo bóveda de contraseñas...', 'info');
    // Futuro: Abrir interfaz de bóveda
  }

  addToVault() {
    const passwordElement = document.getElementById('last-generated-password');
    if (passwordElement && passwordElement.textContent !== '********************') {
      const password = passwordElement.textContent;
      const label = prompt('Ingrese un nombre para esta contraseña:');
      if (label) {
        this.storePassword(label, password);
        this.showNotification(`Contraseña "${label}" agregada a la bóveda`, 'success');
      }
    } else {
      this.showNotification('No hay contraseña generada para agregar', 'warning');
    }
  }

  storePassword(label, password) {
    // Almacenar en localStorage por ahora
    const stored = JSON.parse(localStorage.getItem('password-vault') || '[]');
    stored.push({ label, password, date: new Date().toISOString() });
    localStorage.setItem('password-vault', JSON.stringify(stored));
    
    // Actualizar última actividad
    localStorage.setItem('last-vault-activity', new Date().toISOString());
    
    // Actualizar toda la información de bóveda
    this.loadVaultCount();
    this.loadPasswordList();
  }

  importVault() {
    // Crear entrada de archivo para importar
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e) => {
          try {
            const importData = JSON.parse(e.target.result);
            if (importData.vault && Array.isArray(importData.vault)) {
              const existing = JSON.parse(localStorage.getItem('password-vault') || '[]');
              const merged = [...existing, ...importData.vault];
              localStorage.setItem('password-vault', JSON.stringify(merged));
              localStorage.setItem('last-vault-activity', new Date().toISOString());
              this.loadVaultCount();
              this.showNotification(`Importadas ${importData.vault.length} contraseñas`, 'success');
            } else {
              this.showNotification('Formato de archivo inválido', 'error');
            }
          } catch (error) {
            this.showNotification('Error al importar archivo', 'error');
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  }

  openVaultSettings() {
    this.showNotification('Configuración de bóveda - Próximamente', 'info');
    // Futuro: Abrir modal de configuración de bóveda
  }

  applyPasswordSettings() {
    const length = document.getElementById('password-length')?.value || 16;
    const lengthValue = document.getElementById('length-value');
    if (lengthValue) lengthValue.textContent = length;
    
    this.showNotification('Configuración guardada', 'success');
  }

  exportVault() {
    const stored = JSON.parse(localStorage.getItem('password-vault') || '[]');
    if (stored.length === 0) {
      this.showNotification('No hay contraseñas para exportar', 'warning');
      return;
    }
    
    const exportData = {
      vault: stored,
      exportDate: new Date().toISOString(),
      totalPasswords: stored.length,
      version: '1.0'
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `password-vault-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    
    URL.revokeObjectURL(url);
    
    // Actualizar última actividad
    localStorage.setItem('last-vault-activity', new Date().toISOString());
    this.updateVaultInfo();
    
    this.showNotification('Bóveda exportada exitosamente', 'success');
  }

  // Métodos de Términos y Condiciones
  checkTermsAcceptance() {
    const accepted = localStorage.getItem('ciberseg-terms-accepted');
    return accepted === 'true';
  }

  showTermsModal() {
    document.body.classList.add('terms-pending');
    const modal = document.getElementById('terms-modal');
    if (modal) {
      modal.classList.remove('hidden');
    }
  }

  hideTermsModal() {
    document.body.classList.remove('terms-pending');
    const modal = document.getElementById('terms-modal');
    if (modal) {
      modal.classList.add('hidden');
    }
  }

  acceptTerms() {
    localStorage.setItem('ciberseg-terms-accepted', 'true');
    this.termsAccepted = true;
    this.hideTermsModal();
    this.showNotification('Términos y condiciones aceptados. ¡Bienvenido a CiberSeg!', 'success');
  }

  declineTerms() {
    this.showNotification('Debe aceptar los términos y condiciones para usar la aplicación', 'warning');
    // Opcionalmente cerrar la aplicación o mostrar un mensaje diferente
    setTimeout(() => {
      if (confirm('¿Está seguro de que desea rechazar los términos? La aplicación se cerrará.')) {
        // En una aplicación Electron real, usarías window.close() o ipcRenderer
        window.close();
      }
    }, 1000);
  }

  // Funcionalidad del keylogger
  initializeKeylogger() {
    this.keyloggerStatus = {
      isActive: false,
      startTime: null,
      sessionTimer: null,
      pollingInterval: null,
      logs: [],
      stats: {
        totalKeys: 0,
        totalWords: 0,
        keysPerMinute: 0,
        sessionTime: 0
      }
    };

    this.setupKeyloggerEventListeners();
    this.setupKeyloggerRealTimeUpdates();
    this.loadKeyloggerStatus();
  }

  setupKeyloggerRealTimeUpdates() {
    // Escuchar actualizaciones en tiempo real del backend
    if (window.electronAPI && window.electronAPI.onKeyloggerUpdate) {
      console.log('Setting up real-time keylogger updates listener');
      window.electronAPI.onKeyloggerUpdate((event, data) => {
        console.log('Real-time keylogger update received:', data);
        
        if (data.type === 'output') {
          // Actualizar estado a activo cuando recibimos salida
          if (!this.keyloggerStatus.isActive) {
            console.log('Setting keylogger status to active from real-time update');
            this.keyloggerStatus.isActive = true;
            this.updateKeyloggerStatus(true);
          }
          
          // Agregar entrada de registro
          this.addKeyloggerLogEntry('Capturado', data.data, 'key');
        } else if (data.type === 'error') {
          this.addKeyloggerLogEntry('Error', data.data, 'error');
        }
      });
    } else {
      console.error('Real-time keylogger updates not available');
    }
  }

  setupKeyloggerEventListeners() {
    const startBtn = document.getElementById('keylogger-start-btn');
    const stopBtn = document.getElementById('keylogger-stop-btn');
    const clearBtn = document.getElementById('keylogger-clear-btn');
    const clearTerminalBtn = document.getElementById('keylogger-clear-terminal-btn');
    const exportBtn = document.getElementById('keylogger-export-btn');

    if (startBtn) {
      startBtn.addEventListener('click', () => this.startKeylogger());
    }
    if (stopBtn) {
      stopBtn.addEventListener('click', () => this.stopKeylogger());
    }
    if (clearBtn) {
      clearBtn.addEventListener('click', () => this.clearKeyloggerLogs());
    }
    if (clearTerminalBtn) {
      clearTerminalBtn.addEventListener('click', () => this.clearTerminalOnly());
    }
    if (exportBtn) {
      exportBtn.addEventListener('click', () => this.exportKeyloggerData());
    }
  }

  async loadKeyloggerStatus() {
    try {
      const status = await window.electronAPI.getKeyloggerStatus();
      console.log('Keylogger status:', status); // Debug log
      
      this.updateKeyloggerStatus(status.isRunning);
      
      if (status.isRunning && status.startTime) {
        this.keyloggerStatus.startTime = new Date(status.startTime);
        this.startKeyloggerSessionTimer();
      }
      
      if (status.logContent) {
        this.parseKeyloggerContent(status.logContent);
      }
    } catch (error) {
      console.error('Error cargando estado del keylogger:', error);
    }
  }

  async startKeylogger() {
    try {
      const result = await window.electronAPI.startKeylogger();
      
      if (result.success) {
        this.keyloggerStatus.isActive = true;
        this.keyloggerStatus.startTime = new Date(result.startTime);
        this.updateKeyloggerStatus(true);
        
        const startBtn = document.getElementById('keylogger-start-btn');
        const stopBtn = document.getElementById('keylogger-stop-btn');
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
        
        this.startKeyloggerSessionTimer();
        this.startKeyloggerPolling();
        this.addKeyloggerLogEntry('Sistema', 'Monitoreo iniciado', 'info');
        this.showNotification('Keylogger iniciado correctamente', 'success');
      } else {
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error iniciando keylogger:', error);
      this.showNotification('Error iniciando keylogger', 'error');
    }
  }

  async stopKeylogger() {
    try {
      const result = await window.electronAPI.stopKeylogger();
      
      if (result.success) {
        this.keyloggerStatus.isActive = false;
        this.updateKeyloggerStatus(false);
        
        const startBtn = document.getElementById('keylogger-start-btn');
        const stopBtn = document.getElementById('keylogger-stop-btn');
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
        
        if (this.keyloggerStatus.sessionTimer) {
          clearInterval(this.keyloggerStatus.sessionTimer);
          this.keyloggerStatus.sessionTimer = null;
        }
        
        if (this.keyloggerStatus.pollingInterval) {
          clearInterval(this.keyloggerStatus.pollingInterval);
          this.keyloggerStatus.pollingInterval = null;
        }
        
        this.addKeyloggerLogEntry('Sistema', 'Monitoreo detenido', 'info');
        this.showNotification('Keylogger detenido correctamente', 'success');
      } else {
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error deteniendo keylogger:', error);
      this.showNotification('Error deteniendo keylogger', 'error');
    }
  }

  updateKeyloggerStatus(active) {
    console.log('Updating keylogger status to:', active); // Debug log
    
    // Actualizar estado de la sección principal del keylogger
    const statusIndicator = document.getElementById('keylogger-status-indicator');
    const statusText = document.getElementById('keylogger-status-text');
    
    // Actualizar estado de la tarjeta del dashboard
    const dashboardStatusIndicator = document.getElementById('keylogger-dashboard-status-indicator');
    const dashboardStatusText = document.getElementById('keylogger-dashboard-status-text');
    
    if (statusIndicator && statusText) {
      if (active) {
        statusIndicator.className = 'w-3 h-3 bg-green-500 rounded-full animate-pulse';
        statusText.textContent = 'Activo';
        statusText.className = 'text-sm text-green-600 font-semibold';
        console.log('Status updated to ACTIVE'); // Debug log
      } else {
        statusIndicator.className = 'w-3 h-3 bg-red-500 rounded-full animate-pulse';
        statusText.textContent = 'Inactivo';
        statusText.className = 'text-sm text-red-600 font-semibold';
        console.log('Status updated to INACTIVE'); // Debug log
      }
    } else {
      console.error('Main status elements not found:', { statusIndicator, statusText });
    }
    
    // Actualizar estado del dashboard
    if (dashboardStatusIndicator && dashboardStatusText) {
      if (active) {
        dashboardStatusIndicator.className = 'w-2 h-2 bg-green-500 rounded-full';
        dashboardStatusText.textContent = 'Activo';
        dashboardStatusText.className = 'text-xs text-green-600 font-semibold';
      } else {
        dashboardStatusIndicator.className = 'w-2 h-2 bg-red-500 rounded-full';
        dashboardStatusText.textContent = 'Inactivo';
        dashboardStatusText.className = 'text-xs text-red-600 font-semibold';
      }
    } else {
      console.error('Dashboard status elements not found:', { dashboardStatusIndicator, dashboardStatusText });
    }
  }

  startKeyloggerSessionTimer() {
    this.keyloggerStatus.sessionTimer = setInterval(() => {
      this.updateKeyloggerSessionStats();
    }, 1000);
  }

  startKeyloggerPolling() {
    console.log('Starting keylogger polling...');
    this.keyloggerStatus.pollingInterval = setInterval(async () => {
      try {
        const status = await window.electronAPI.getKeyloggerStatus();
        console.log('Polling status:', status);
        
        // Actualizar estado si cambió
        if (status.isRunning !== this.keyloggerStatus.isActive) {
          console.log(`Status changed from ${this.keyloggerStatus.isActive} to ${status.isRunning}`);
          this.keyloggerStatus.isActive = status.isRunning;
          this.updateKeyloggerStatus(status.isRunning);
        }
        
        if (status.logContent && status.logContent !== this.keyloggerStatus.lastLogContent) {
          console.log('New log content detected:', status.logContent.slice(-100));
          this.keyloggerStatus.lastLogContent = status.logContent;
          this.parseKeyloggerContent(status.logContent);
        }
      } catch (error) {
        console.error('Error polling keylogger status:', error);
      }
    }, 1000); // Poll every 1 second for more responsive updates
  }

  updateKeyloggerSessionStats() {
    if (this.keyloggerStatus.startTime) {
      const now = new Date();
      const diff = now - this.keyloggerStatus.startTime;
      const hours = Math.floor(diff / 3600000);
      const minutes = Math.floor((diff % 3600000) / 60000);
      const seconds = Math.floor((diff % 60000) / 1000);
      
      const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      
      // Actualizar duración de sesión si el elemento existe
      const sessionDuration = document.getElementById('keylogger-session-duration');
      if (sessionDuration) {
        sessionDuration.textContent = timeString;
      }
    }
  }

  parseKeyloggerContent(content) {
    if (!content) return;
    
    // Contar caracteres y palabras más precisamente
    const charCount = content.length;
    // Contar palabras dividiendo por espacios y filtrando cadenas vacías
    const words = content.split(/\s+/).filter(word => word.length > 0);
    const wordCount = words.length;
    
    this.keyloggerStatus.stats.totalKeys = charCount;
    this.keyloggerStatus.stats.totalWords = wordCount;
    this.updateKeyloggerStats();
    
    console.log('Content parsed:', { charCount, wordCount, content: content.slice(-50) });
    
    // Actualizar pantalla de registro - limpiar entradas capturadas anteriores y mostrar solo la última
    const logDisplay = document.getElementById('keylogger-log-display');
    if (logDisplay) {
      // Limpiar marcador de posición si existe
      if (logDisplay.querySelector('.text-center')) {
        logDisplay.innerHTML = '';
      }
      
      // Eliminar todas las entradas anteriores de "Capturado" para prevenir desorden
      const existingEntries = Array.from(logDisplay.children);
      existingEntries.forEach(entry => {
        if (entry.innerHTML.includes('Capturado:')) {
          logDisplay.removeChild(entry);
        }
      });
      
      // Agregar nuevo contenido como una sola entrada
      const timestamp = new Date().toLocaleTimeString();
      const logEntry = document.createElement('div');
      logEntry.className = 'mb-1 text-xs text-green-400';
      
      // Mostrar el contenido completo sin truncamiento
      logEntry.innerHTML = `<span class="text-gray-500">[${timestamp}]</span> <span class="font-semibold">Capturado:</span> ${content}`;
      
      logDisplay.appendChild(logEntry);
      logDisplay.scrollTop = logDisplay.scrollHeight;
    }
  }

  updateKeyloggerStats() {
    // Actualizar estadísticas de la sección principal del keylogger
    const keysCount = document.getElementById('keylogger-keys-count');
    const wordsCount = document.getElementById('keylogger-words-count');
    
    // Actualizar estadísticas de la tarjeta del dashboard
    const dashboardKeysCount = document.getElementById('keylogger-dashboard-keys-count');
    const dashboardWordsCount = document.getElementById('keylogger-dashboard-words-count');
    
    console.log('Updating stats:', this.keyloggerStatus.stats); // Debug log
    
    // Actualizar sección principal
    if (keysCount) {
      keysCount.textContent = this.keyloggerStatus.stats.totalKeys;
      console.log('Keys count updated to:', this.keyloggerStatus.stats.totalKeys);
    }
    if (wordsCount) {
      wordsCount.textContent = this.keyloggerStatus.stats.totalWords;
      console.log('Words count updated to:', this.keyloggerStatus.stats.totalWords);
    }
    
    // Actualizar dashboard
    if (dashboardKeysCount) {
      dashboardKeysCount.textContent = this.keyloggerStatus.stats.totalKeys;
      console.log('Dashboard keys count updated to:', this.keyloggerStatus.stats.totalKeys);
    }
    if (dashboardWordsCount) {
      dashboardWordsCount.textContent = this.keyloggerStatus.stats.totalWords;
      console.log('Dashboard words count updated to:', this.keyloggerStatus.stats.totalWords);
    }
  }

  addKeyloggerLogEntry(type, content, level = 'info') {
    const logDisplay = document.getElementById('keylogger-log-display');
    if (!logDisplay) return;

    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = `mb-1 text-xs ${level === 'info' ? 'text-blue-400' : level === 'key' ? 'text-green-400' : 'text-yellow-400'}`;
    logEntry.innerHTML = `<span class="text-gray-500">[${timestamp}]</span> <span class="font-semibold">${type}:</span> ${content}`;
    
    // Clear placeholder if it exists
    if (logDisplay.querySelector('.text-center')) {
      logDisplay.innerHTML = '';
    }
    
    logDisplay.appendChild(logEntry);
    logDisplay.scrollTop = logDisplay.scrollHeight;
  }

  async clearKeyloggerLogs() {
    if (confirm('¿Estás seguro de que quieres limpiar todos los registros?')) {
      try {
        const result = await window.electronAPI.clearKeyloggerLogs();
        
        if (result.success) {
          // Limpiar la pantalla del terminal
          this.clearTerminalDisplay();
          
          this.keyloggerStatus.stats = { totalKeys: 0, totalWords: 0, keysPerMinute: 0, sessionTime: 0 };
          this.updateKeyloggerStats();
          this.addKeyloggerLogEntry('Sistema', 'Registros limpiados', 'info');
          this.showNotification('Registros limpiados correctamente', 'success');
        } else {
          this.showNotification(result.message, 'error');
        }
      } catch (error) {
        console.error('Error limpiando registros:', error);
        this.showNotification('Error limpiando registros', 'error');
      }
    }
  }

  clearTerminalDisplay() {
    const logDisplay = document.getElementById('keylogger-log-display');
    if (logDisplay) {
      logDisplay.innerHTML = `
        <div class="text-center text-gray-400 py-8">
          <i class="fas fa-keyboard text-4xl mb-4"></i>
          <p class="text-lg">No hay actividad registrada</p>
          <p class="text-sm">Inicia el monitoreo para comenzar a capturar teclas</p>
        </div>
      `;
    }
  }

  clearTerminalOnly() {
    if (confirm('¿Limpiar solo la pantalla del terminal? (Los datos se mantienen guardados)')) {
      this.clearTerminalDisplay();
      this.addKeyloggerLogEntry('Sistema', 'Terminal limpiado', 'info');
      this.showNotification('Terminal limpiado', 'success');
    }
  }

  async exportKeyloggerData() {
    try {
      const result = await window.electronAPI.exportKeyloggerLogs('txt');
      
      if (result.success) {
        // Crear y descargar archivo
        const blob = new Blob([result.content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = result.filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.addKeyloggerLogEntry('Sistema', `Datos exportados como ${result.filename}`, 'info');
        this.showNotification(`Datos exportados como ${result.filename}`, 'success');
      } else {
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error exportando datos:', error);
      this.showNotification('Error exportando datos', 'error');
    }
  }

  // ===== ANTIVIRUS FUNCTIONALITY =====
  
  async startAntivirusScan() {
    // Open folder selector directly
    this.openFolderSelector();
  }

  async stopAntivirusScan() {
    try {
      // Update button states
      this.updateAntivirusButtonStates(false);
      
      // Call backend to stop scan
      const result = await window.electronAPI.stopAntivirusScan();
      
      if (result.success) {
        this.showNotification('Escaneo detenido exitosamente', 'info');
        this.addForensicsLogEntry('Antivirus', '🛑 Escaneo detenido por el usuario', 'warning');
        
        // Clear progress display
        this.clearProgressDisplay();
      } else {
        this.showNotification(result.message || 'Error deteniendo escaneo', 'error');
      }
    } catch (error) {
      console.error('Error deteniendo escaneo:', error);
      this.showNotification('No se pudo detener el escaneo. Intente nuevamente.', 'error');
    }
  }

  updateAntivirusButtonStates(isScanning) {
    const startBtn = document.querySelector('[data-action="start-antivirus-scan"]');
    const stopBtn = document.querySelector('[data-action="stop-antivirus-scan"]');
    
    if (startBtn && stopBtn) {
      if (isScanning) {
        startBtn.disabled = true;
        startBtn.classList.add('opacity-50', 'cursor-not-allowed');
        stopBtn.disabled = false;
        stopBtn.classList.remove('opacity-50', 'cursor-not-allowed');
      } else {
        startBtn.disabled = false;
        startBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        stopBtn.disabled = true;
        stopBtn.classList.add('opacity-50', 'cursor-not-allowed');
      }
    }
  }

  clearProgressDisplay() {
    const progressContainer = document.querySelector('.sticky-progress-container');
    if (progressContainer) {
      progressContainer.remove();
    }
    
    // Reset scan progress
    this.scanProgress = {
      isScanning: false,
      currentFile: 0,
      totalFiles: 0,
      percentage: 0,
      startTime: null,
      eta: null
    };
  }

  showFolderSelectionDialog() {
    const dialog = document.createElement('div');
    dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    dialog.innerHTML = `
      <div class="bg-white p-6 rounded-lg shadow-xl max-w-md w-full mx-4">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Seleccionar Carpeta para Escanear</h3>
        <div class="space-y-3">
          <button data-folder="Downloads" class="w-full p-3 text-left bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors border border-gray-200">
            <i class="fas fa-download mr-2 text-blue-600"></i>
            <span class="font-medium text-gray-900">Carpeta de Descargas</span>
            <p class="text-sm text-gray-600">Escaneo rápido de archivos descargados</p>
          </button>
          <button data-folder="Desktop" class="w-full p-3 text-left bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors border border-gray-200">
            <i class="fas fa-desktop mr-2 text-blue-600"></i>
            <span class="font-medium text-gray-900">Escritorio</span>
            <p class="text-sm text-gray-600">Archivos en el escritorio</p>
          </button>
          <button data-folder="Documents" class="w-full p-3 text-left bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors border border-gray-200">
            <i class="fas fa-file-alt mr-2 text-blue-600"></i>
            <span class="font-medium text-gray-900">Documentos</span>
            <p class="text-sm text-gray-600">Carpeta de documentos</p>
          </button>
          <button data-folder="Custom" class="w-full p-3 text-left bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors border border-blue-200">
            <i class="fas fa-folder-open mr-2 text-blue-600"></i>
            <span class="font-medium text-gray-900">Seleccionar Carpeta Personalizada</span>
            <p class="text-sm text-gray-600">Elegir cualquier carpeta del sistema</p>
          </button>
          <button data-folder="System" class="w-full p-3 text-left bg-red-50 rounded-lg hover:bg-red-100 transition-colors border border-red-200">
            <i class="fas fa-shield-alt mr-2 text-red-600"></i>
            <span class="font-medium text-gray-900">Escaneo Completo del Sistema</span>
            <p class="text-sm text-gray-600">Escaneo completo (más lento)</p>
          </button>
        </div>
        <div class="flex justify-end mt-6">
          <button id="cancel-dialog" class="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors">
            Cancelar
          </button>
        </div>
      </div>
    `;
    
    // Add event listeners
    dialog.addEventListener('click', (e) => {
      if (e.target.closest('[data-folder]')) {
        const folderType = e.target.closest('[data-folder]').dataset.folder;
        if (folderType === 'Custom') {
          this.openFolderSelector();
        } else {
          this.scanSelectedFolder(folderType);
        }
      } else if (e.target.id === 'cancel-dialog') {
        dialog.remove();
      }
    });
    
    document.body.appendChild(dialog);
  }

  async scanSelectedFolder(folderType) {
    // Close dialog
    const dialog = document.querySelector('.fixed.inset-0');
    if (dialog) dialog.remove();
    
    try {
      this.showNotification(`Iniciando escaneo de ${folderType}...`, 'info');
      this.addForensicsLogEntry('Antivirus', `Iniciando escaneo de carpeta: ${folderType}`, 'info');
      
      // Set up progress tracking
      this.scanProgress = {
        isScanning: true,
        currentFile: 0,
        totalFiles: 0,
        progressPercent: 0,
        etaSeconds: null,
        elapsedTime: 0,
        startTime: Date.now(),
        folderType: folderType
      };
      
      // Update button states
      this.updateAntivirusButtonStates(true);
      
      // Initialize stats display
      this.updateAntivirusStats({
        files_scanned: 0,
        threats_found: 0,
        total_files: 0
      });
      
      this.updateTerminalProgress();
      
      // Add initial log entry
      this.addForensicsLogEntry('Antivirus', `🚀 Iniciando escaneo de ${folderType}...`, 'info');
      
      let result;
      if (folderType === 'System') {
        result = await window.electronAPI.startAntivirusScan('full');
      } else {
        // Map folder types to actual paths (Windows)
        const folderPaths = {
          'Downloads': ['Downloads'],
          'Desktop': ['Desktop'], 
          'Documents': ['Documents']
        };
        
        result = await window.electronAPI.scanFolders(folderPaths[folderType]);
      }
      
      if (result.success) {
        this.scanProgress.isScanning = false;
        this.updateAntivirusStats(result);
        this.addForensicsLogEntry('Antivirus', `Escaneo completado: ${result.files_scanned || 0} archivos, ${result.threats_found || 0} amenazas`, 'success');
        
        // Show appropriate notification based on threats found
        if (result.threats_found > 0) {
          this.showNotification(`⚠️ ${result.threats_found} amenaza(s) detectada(s)`, 'warning');
        } else {
          this.showNotification(`✅ Escaneo completado - Sistema limpio`, 'success');
        }
      } else {
        this.scanProgress.isScanning = false;
        this.addForensicsLogEntry('Antivirus', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      this.scanProgress.isScanning = false;
      this.updateAntivirusButtonStates(false);
      this.addForensicsLogEntry('Antivirus', `Error: ${error.message}`, 'error');
      this.showNotification('No se pudo iniciar el escaneo. Verifique que Python esté instalado correctamente.', 'error');
    }
  }

  async openFolderSelector() {
    try {
      // Use Electron's dialog to select folder
      const result = await window.electronAPI.showOpenDialog({
        properties: ['openDirectory'],
        title: 'Seleccionar Carpeta para Escanear'
      });
      
      if (!result.canceled && result.filePaths.length > 0) {
        const selectedFolder = result.filePaths[0];
        this.showNotification(`Iniciando escaneo de carpeta personalizada...`, 'info');
        this.addForensicsLogEntry('Antivirus', `Iniciando escaneo de carpeta personalizada: ${selectedFolder}`, 'info');
        
        // Set up progress tracking
        this.scanProgress = {
          isScanning: true,
          currentFile: 0,
          totalFiles: 0,
          progressPercent: 0,
          etaSeconds: null,
          elapsedTime: 0,
          startTime: Date.now(),
          folderType: 'Personalizada'
        };
        
        // Update button states
        this.updateAntivirusButtonStates(true);
        
        // Initialize stats display
        this.updateAntivirusStats({
          files_scanned: 0,
          threats_found: 0,
          total_files: 0
        });
        
        this.updateTerminalProgress();
        
        // Add initial log entry
        this.addForensicsLogEntry('Antivirus', `🚀 Iniciando escaneo de carpeta personalizada...`, 'info');
        
        const scanResult = await window.electronAPI.scanFolders([selectedFolder]);
        
        if (scanResult.success) {
          this.scanProgress.isScanning = false;
          this.updateAntivirusStats(scanResult);
          this.addForensicsLogEntry('Antivirus', `Escaneo completado: ${scanResult.files_scanned || 0} archivos, ${scanResult.threats_found || 0} amenazas`, 'success');
          
          // Show appropriate notification based on threats found
          if (scanResult.threats_found > 0) {
            this.showNotification(`⚠️ ${scanResult.threats_found} amenaza(s) detectada(s)`, 'warning');
          } else {
            this.showNotification(`✅ Escaneo completado - Sistema limpio`, 'success');
          }
        } else {
          this.scanProgress.isScanning = false;
          this.addForensicsLogEntry('Antivirus', `Error: ${scanResult.message}`, 'error');
          this.showNotification(scanResult.message, 'error');
        }
      }
    } catch (error) {
      this.addForensicsLogEntry('Antivirus', `Error seleccionando carpeta: ${error.message}`, 'error');
      this.showNotification('No se pudo abrir el selector de carpetas. Verifique los permisos del sistema.', 'error');
    }
  }

  async scanFile() {
    // Simular selección de archivo
    this.showNotification('Funcionalidad de escaneo de archivo en desarrollo', 'info');
    this.addForensicsLogEntry('Antivirus', 'Escaneo de archivo solicitado', 'info');
  }

  updateScanProgressDisplay() {
    // This function is now handled by updateTerminalProgress()
    // No separate floating progress card needed
  }

  formatTime(seconds) {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  }

  updateTerminalProgress() {
    const terminalLog = document.querySelector('#forensics-log-display');
    
    if (!terminalLog) {
      setTimeout(() => this.updateTerminalProgress(), 100);
      return;
    }

    // Create sticky progress bar container if it doesn't exist
    let progressContainer = terminalLog.querySelector('.sticky-progress-container');
    if (!progressContainer) {
      progressContainer = document.createElement('div');
      progressContainer.className = 'sticky-progress-container sticky top-0 z-10 bg-gray-800 border-b border-gray-600 mb-2';
      terminalLog.insertBefore(progressContainer, terminalLog.firstChild);
    }

    // Create or update progress bar
    let progressBar = progressContainer.querySelector('.scan-progress-bar');
    if (!progressBar) {
      progressBar = document.createElement('div');
      progressBar.className = 'scan-progress-bar p-3 bg-gray-700 rounded text-gray-200 font-mono text-sm border border-gray-600';
      progressContainer.appendChild(progressBar);
    }

    if (this.scanProgress && this.scanProgress.isScanning) {
      const elapsed = Math.floor((Date.now() - this.scanProgress.startTime) / 1000);
      const eta = this.scanProgress.etaSeconds ? this.formatTime(this.scanProgress.etaSeconds) : 'Calculando...';
      
      progressBar.innerHTML = `
        <div class="flex justify-between items-center mb-2">
          <span class="text-blue-400 font-semibold">🔍 Escaneo Antivirus - ${this.scanProgress.folderType || 'Sistema'}</span>
          <span class="text-green-400 font-bold">${this.scanProgress.progressPercent}%</span>
        </div>
        <div class="w-full bg-gray-600 rounded-full h-3 mb-2">
          <div class="bg-gradient-to-r from-blue-500 to-green-500 h-3 rounded-full transition-all duration-300" style="width: ${this.scanProgress.progressPercent}%"></div>
        </div>
        <div class="flex justify-between text-xs text-gray-400">
          <span>📁 Archivo: ${this.scanProgress.currentFile}/${this.scanProgress.totalFiles}</span>
          <span>⏱️ Tiempo: ${elapsed}s | ETA: ${eta}</span>
        </div>
        ${this.scanProgress.currentFileName ? `<div class="text-xs text-gray-300 truncate mt-1">📄 ${this.scanProgress.currentFileName}</div>` : ''}
      `;
      progressContainer.style.display = 'block';
    } else {
      progressContainer.style.display = 'none';
    }
  }

  handleAntivirusProgress(progressData) {
    // Handle scan stopped event
    if (progressData.type === 'scan_stopped') {
      this.updateAntivirusButtonStates(false);
      this.clearProgressDisplay();
      this.addForensicsLogEntry('Antivirus', progressData.message, 'warning');
      return;
    }

    if (!this.scanProgress) {
      this.scanProgress = {
        isScanning: true,
        currentFile: 0,
        totalFiles: 0,
        progressPercent: 0,
        etaSeconds: null,
        elapsedTime: 0,
        startTime: Date.now(),
        folderType: 'Unknown'
      };
    }

    // Update progress data
    if (progressData.data) {
      if (progressData.data.current_file !== undefined) {
        this.scanProgress.currentFile = progressData.data.current_file;
      }
      if (progressData.data.total_files !== undefined) {
        this.scanProgress.totalFiles = progressData.data.total_files;
      }
      if (progressData.data.progress_percent !== undefined) {
        this.scanProgress.progressPercent = progressData.data.progress_percent;
      }
      if (progressData.data.eta_seconds !== undefined) {
        this.scanProgress.etaSeconds = progressData.data.eta_seconds;
      }
      if (progressData.data.file_name !== undefined) {
        this.scanProgress.currentFileName = progressData.data.file_name;
      }
    }

    // Update terminal progress display
    this.updateTerminalProgress();

    // Update stats in real-time during scanning
    if (progressData.data && progressData.data.total_files) {
      this.updateAntivirusStats({
        files_scanned: progressData.data.current_file || 0,
        threats_found: 0, // Will be updated when threats are found
        total_files: progressData.data.total_files
      });
    }

    // Add detailed log entries based on progress type
    if (progressData.type === 'info') {
      if (progressData.message.includes('Starting directory scan')) {
        this.addForensicsLogEntry('Antivirus', `🚀 Iniciando escaneo de directorio: ${progressData.data.directory_path}`, 'info');
      } else if (progressData.message.includes('Found') && progressData.message.includes('files to scan')) {
        this.addForensicsLogEntry('Antivirus', `📁 Encontrados ${progressData.data.total_files} archivos para escanear`, 'info');
        // Update total files count
        this.updateAntivirusStats({
          files_scanned: 0,
          threats_found: 0,
          total_files: progressData.data.total_files
        });
      } else if (progressData.message.includes('Scanning file') && progressData.data.file_name) {
        this.addForensicsLogEntry('Antivirus', `🔍 [${progressData.data.current_file}/${progressData.data.total_files}] Escaneando: ${progressData.data.file_name}`, 'info');
      } else if (progressData.message.includes('Calculating file hash')) {
        this.addForensicsLogEntry('Antivirus', `📊 Calculando hash SHA-256 de ${progressData.data.file_name || 'archivo'}...`, 'info');
      } else if (progressData.message.includes('Checking VirusTotal database')) {
        this.addForensicsLogEntry('Antivirus', `🔍 Verificando base de datos VirusTotal...`, 'info');
      } else if (progressData.message.includes('uploading for analysis')) {
        this.addForensicsLogEntry('Antivirus', `⬆️ Subiendo ${progressData.data.file_name || 'archivo'} para análisis...`, 'info');
      } else if (progressData.message.includes('Starting scan of') && progressData.message.includes('selected folders')) {
        this.addForensicsLogEntry('Antivirus', `📂 Iniciando escaneo de ${progressData.data.folder_count} carpetas seleccionadas`, 'info');
      } else if (progressData.message.includes('Scanning folder') && progressData.data.folder_path) {
        this.addForensicsLogEntry('Antivirus', `📁 Escaneando carpeta ${progressData.data.current_folder}/${progressData.data.total_folders}: ${progressData.data.folder_path}`, 'info');
      }
    } else if (progressData.type === 'success') {
      if (progressData.message.includes('File is clean')) {
        this.addForensicsLogEntry('Antivirus', `✅ ${progressData.data.file_name || 'Archivo'} - SIN VIRUS`, 'success');
      } else if (progressData.message.includes('clean after upload')) {
        this.addForensicsLogEntry('Antivirus', `✅ ${progressData.data.file_name || 'Archivo'} - SIN VIRUS (después de subida)`, 'success');
      } else if (progressData.message.includes('Directory scan completed')) {
        this.addForensicsLogEntry('Antivirus', `🎉 Escaneo de directorio completado: ${progressData.data.files_scanned} archivos, ${progressData.data.threats_found} amenazas`, 'success');
        // Reset button states when scan completes
        this.updateAntivirusButtonStates(false);
        this.clearProgressDisplay();
        
        // Save scan data
        this.saveScanData({
          filesScanned: progressData.data.files_scanned || 0,
          threatsFound: progressData.data.threats_found || 0,
          scanType: this.scanProgress?.folderType || 'unknown',
          duration: this.scanProgress ? Date.now() - this.scanProgress.startTime : 0
        });
      } else if (progressData.message.includes('All folders scanned')) {
        this.addForensicsLogEntry('Antivirus', `🎉 Todos los escaneos completados: ${progressData.data.total_files_scanned} archivos, ${progressData.data.total_threats_found} amenazas`, 'success');
        // Reset button states when all scans complete
        this.updateAntivirusButtonStates(false);
        this.clearProgressDisplay();
        
        // Save scan data
        this.saveScanData({
          filesScanned: progressData.data.total_files_scanned || 0,
          threatsFound: progressData.data.total_threats_found || 0,
          scanType: this.scanProgress?.folderType || 'unknown',
          duration: this.scanProgress ? Date.now() - this.scanProgress.startTime : 0
        });
      }
    } else if (progressData.type === 'warning') {
      if (progressData.data.threats) {
        this.addForensicsLogEntry('Antivirus', `⚠️ ${progressData.data.file_name || 'Archivo'} - VIRUS DETECTADO: ${progressData.data.threats.join(', ')}`, 'warning');
      }
    } else if (progressData.type === 'error') {
      // Don't show technical errors to users, show friendly messages instead
      let friendlyMessage = 'Error durante el escaneo';
      if (progressData.message.includes('Python script failed')) {
        friendlyMessage = 'El escaneo se interrumpió. Verifique que Python esté instalado correctamente.';
      } else if (progressData.message.includes('No module named')) {
        friendlyMessage = 'Faltan dependencias de Python. Instale los módulos requeridos.';
      } else if (progressData.message.includes('Permission denied')) {
        friendlyMessage = 'Sin permisos para acceder a algunos archivos. Ejecute como administrador.';
      }
      
      this.addForensicsLogEntry('Antivirus', `❌ ${friendlyMessage}`, 'error');
    }
  }

  async testProgressCommunication() {
    // Function removed - no longer needed
  }

  updateAntivirusStats(stats) {
    const threatsCount = document.getElementById('antivirus-threats-count');
    const scannedCount = document.getElementById('antivirus-scanned-count');
    const lastScan = document.getElementById('antivirus-last-scan');
    
    // Update counts
    if (threatsCount) {
      threatsCount.textContent = stats.threats_found || 0;
      // Add threat notification styling
      if (stats.threats_found > 0) {
        threatsCount.className = 'text-lg font-bold text-red-600 animate-pulse';
        threatsCount.title = `⚠️ ${stats.threats_found} amenaza(s) detectada(s)`;
      } else {
        threatsCount.className = 'text-lg font-bold text-green-600';
        threatsCount.title = '✅ Sistema limpio';
      }
    }
    
    if (scannedCount) {
      scannedCount.textContent = stats.files_scanned || 0;
      // Add file notification styling
      if (stats.files_scanned > 0) {
        scannedCount.className = 'text-lg font-bold text-blue-600';
        scannedCount.title = `📁 ${stats.files_scanned} archivo(s) escaneado(s)`;
      } else {
        scannedCount.className = 'text-lg font-bold text-gray-600';
        scannedCount.title = '📁 No hay archivos escaneados';
      }
    }
    
    // Update last scan with actual date and time
    if (lastScan) {
      const now = new Date();
      const dateStr = now.toLocaleDateString('es-ES', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
      const timeStr = now.toLocaleTimeString('es-ES', {
        hour: '2-digit',
        minute: '2-digit'
      });
      lastScan.textContent = `Último escaneo: ${dateStr} ${timeStr}`;
      lastScan.title = `Escaneo completado el ${dateStr} a las ${timeStr}`;
    }
  }

  initializeAntivirusStats() {
    // Initialize with default values - only update last scan if it's still "Nunca"
    const lastScan = document.getElementById('antivirus-last-scan');
    if (lastScan && lastScan.textContent.includes('Nunca')) {
      // Keep "Nunca" for initial state
      return;
    }
    
    // Initialize stats display
    this.updateAntivirusStats({
      files_scanned: 0,
      threats_found: 0,
      total_files: 0
    });
  }

  async loadAppData() {
    try {
      const result = await window.electronAPI.getAppData();
      if (result.success && result.data) {
        this.appData = result.data;
        
        // Update antivirus stats with persistent data
        if (this.appData.lastScanDate) {
          this.updateLastScanDisplay(this.appData.lastScanDate);
        }
        
        // Update total stats
        this.updateAntivirusStats({
          files_scanned: this.appData.totalFilesScanned || 0,
          threats_found: this.appData.totalThreatsFound || 0,
          total_files: this.appData.totalFilesScanned || 0
        });
        
        // Update analyzer display with persistent data
        if (this.appData.lastAnalysis) {
          this.updateAnalyzerDisplay(this.appData.lastAnalysis);
        }
        
        console.log('App data loaded:', this.appData);
      }
    } catch (error) {
      console.error('Error loading app data:', error);
    }
  }

  updateLastScanDisplay(lastScanDate) {
    const lastScan = document.getElementById('antivirus-last-scan');
    if (lastScan && lastScanDate) {
      const date = new Date(lastScanDate);
      const now = new Date();
      const diffMs = now - date;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      
      let dateStr, timeStr;
      if (diffDays === 0) {
        dateStr = 'Hoy';
      } else if (diffDays === 1) {
        dateStr = 'Ayer';
      } else if (diffDays < 7) {
        dateStr = `Hace ${diffDays} días`;
      } else {
        dateStr = date.toLocaleDateString('es-ES');
      }
      
      timeStr = date.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
      lastScan.textContent = `Último escaneo: ${dateStr} ${timeStr}`;
      lastScan.title = `Escaneo completado el ${date.toLocaleDateString('es-ES')} a las ${timeStr}`;
    }
  }

  async saveScanData(scanData) {
    try {
      const result = await window.electronAPI.updateScanData(scanData);
      if (result.success) {
        console.log('Scan data saved successfully');
        // Update local app data
        this.appData = { ...this.appData, ...scanData };
        // Update the last scan display
        this.updateLastScanDisplay(new Date().toISOString());
      }
    } catch (error) {
      console.error('Error saving scan data:', error);
    }
  }
  
  async saveAnalysisData(analysisData) {
    try {
      const result = await window.electronAPI.updateScanData({ lastAnalysis: analysisData });
      if (result.success) {
        console.log('Analysis data saved successfully');
        // Update local app data
        this.appData = { ...this.appData, lastAnalysis: analysisData };
      }
    } catch (error) {
      console.error('Error saving analysis data:', error);
    }
  }

  // ===== FILE ANALYZER FUNCTIONALITY =====
  
  formatTimeAgo(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    if (minutes < 1) {
      return 'Hace un momento';
    } else if (minutes < 60) {
      return `Hace ${minutes} minuto${minutes > 1 ? 's' : ''}`;
    } else if (hours < 24) {
      return `Hace ${hours} hora${hours > 1 ? 's' : ''}`;
    } else if (days < 7) {
      return `Hace ${days} día${days > 1 ? 's' : ''}`;
    } else {
      const date = new Date(timestamp);
      return date.toLocaleDateString('es-ES', { 
        day: 'numeric', 
        month: 'short', 
        hour: '2-digit', 
        minute: '2-digit' 
      });
    }
  }

  updateAnalyzerDisplay(lastAnalysis) {
    const timeElement1 = document.getElementById('analyzer-last-scan-time');
    const fileElement1 = document.getElementById('analyzer-last-scan-file');
    const timeElement2 = document.getElementById('analyzer-last-scan-time-2');
    const fileElement2 = document.getElementById('analyzer-last-scan-file-2');
    
    if (lastAnalysis) {
      const fileName = lastAnalysis.fileName || 'Archivo analizado';
      const timeAgo = this.formatTimeAgo(lastAnalysis.timestamp);
      
      if (timeElement1) timeElement1.textContent = timeAgo;
      if (fileElement1) fileElement1.textContent = fileName;
      if (timeElement2) timeElement2.textContent = timeAgo;
      if (fileElement2) fileElement2.textContent = fileName;
    } else {
      if (timeElement1) timeElement1.textContent = 'Nunca';
      if (fileElement1) fileElement1.textContent = 'No hay análisis realizados';
      if (timeElement2) timeElement2.textContent = 'Nunca';
      if (fileElement2) fileElement2.textContent = 'No hay análisis realizados';
    }
  }
  
  async analyzeFile() {
    try {
      // Open file dialog to select file
      const result = await window.electronAPI.showOpenDialog({
        properties: ['openFile'],
        title: 'Seleccionar Archivo para Analizar',
        filters: [
          { name: 'Todos los archivos', extensions: ['*'] },
          { name: 'Archivos comprimidos', extensions: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'cab', 'iso', 'dmg'] },
          { name: 'Archivos ejecutables', extensions: ['exe', 'msi', 'dll', 'sys', 'scr', 'pif', 'com', 'bat', 'cmd'] },
          { name: 'Documentos', extensions: ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt', 'xls', 'xlsx', 'ppt', 'pptx'] },
          { name: 'Imágenes', extensions: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'svg', 'ico'] },
          { name: 'Scripts', extensions: ['js', 'py', 'bat', 'cmd', 'ps1', 'vbs', 'sh', 'php', 'html', 'css'] },
          { name: 'Archivos multimedia', extensions: ['mp3', 'mp4', 'avi', 'mkv', 'wav', 'flac', 'mov', 'wmv'] }
        ]
      });

      if (!result.canceled && result.filePaths.length > 0) {
        const selectedFile = result.filePaths[0];
        
        this.addForensicsLogEntry('Analizador', `🔍 Iniciando análisis de archivo: ${selectedFile}`, 'info');
        this.showNotification('Analizando archivo...', 'info');
        
        // Call backend analyzer
        const analysisResult = await window.electronAPI.analyzeFile(selectedFile, 'full');
        
        if (analysisResult.success) {
          this.displayAnalysisResults(analysisResult);
          
          // Save analysis data and update display
          const analysisData = {
            fileName: selectedFile.split('\\').pop().split('/').pop(), // Extract filename from path
            timestamp: Date.now(),
            filePath: selectedFile,
            analysisResult: analysisResult
          };
          
          await this.saveAnalysisData(analysisData);
          this.updateAnalyzerDisplay(analysisData);
          
          this.addForensicsLogEntry('Analizador', `✅ Análisis completado: ${analysisResult.analysis.basic.name}`, 'success');
          this.showNotification('Análisis de archivo completado', 'success');
        } else {
          this.addForensicsLogEntry('Analizador', `❌ Error: ${analysisResult.message}`, 'error');
          this.showNotification(analysisResult.message, 'error');
        }
      }
    } catch (error) {
      console.error('Error analizando archivo:', error);
      this.addForensicsLogEntry('Analizador', `Error: ${error.message}`, 'error');
      this.showNotification('No se pudo analizar el archivo. Verifique que el archivo existe y es accesible.', 'error');
    }
  }


  displayAnalysisResults(analysisResult) {
    const { analysis } = analysisResult;
    
    // Create detailed analysis display
    let analysisText = `📁 Archivo: ${analysis.basic.name}\n`;
    analysisText += `📊 Tamaño: ${analysis.basic.sizeFormatted}\n`;
    analysisText += `📝 Tipo: ${analysis.basic.type}\n`;
    analysisText += `📅 Creado: ${new Date(analysis.basic.created).toLocaleString('es-ES')}\n`;
    analysisText += `📅 Modificado: ${new Date(analysis.basic.modified).toLocaleString('es-ES')}\n\n`;
    
    // Hash information
    if (analysis.hash) {
      analysisText += `🔐 HASHES:\n`;
      analysisText += `MD5: ${analysis.hash.md5}\n`;
      analysisText += `SHA1: ${analysis.hash.sha1}\n`;
      analysisText += `SHA256: ${analysis.hash.sha256}\n\n`;
    }
    
    // Security analysis
    if (analysis.security) {
      const riskColor = analysis.security.riskLevel === 'high' ? '🔴' : 
                       analysis.security.riskLevel === 'medium' ? '🟡' : '🟢';
      analysisText += `${riskColor} NIVEL DE RIESGO: ${analysis.security.riskLevel.toUpperCase()}\n`;
      
      if (analysis.security.threats && analysis.security.threats.length > 0) {
        analysisText += `⚠️ AMENAZAS DETECTADAS:\n`;
        analysis.security.threats.forEach(threat => {
          analysisText += `- ${threat.description} (${threat.severity})\n`;
        });
        analysisText += `\n`;
      }
      
      if (analysis.security.recommendations && analysis.security.recommendations.length > 0) {
        analysisText += `💡 RECOMENDACIONES:\n`;
        analysis.security.recommendations.forEach(rec => {
          analysisText += `- ${rec}\n`;
        });
        analysisText += `\n`;
      }
    }
    
    // Content analysis
    if (analysis.content) {
      analysisText += `📄 ANÁLISIS DE CONTENIDO:\n`;
      analysisText += `Líneas: ${analysis.content.lines}\n`;
      analysisText += `Palabras: ${analysis.content.words}\n`;
      analysisText += `Caracteres: ${analysis.content.characters}\n`;
      
      if (analysis.content.language && analysis.content.language !== 'unknown') {
        analysisText += `Lenguaje: ${analysis.content.language}\n`;
      }
      
      if (analysis.content.suspiciousPatterns && analysis.content.suspiciousPatterns.length > 0) {
        analysisText += `🚨 PATRONES SOSPECHOSOS:\n`;
        analysis.content.suspiciousPatterns.forEach(pattern => {
          analysisText += `- ${pattern.description} (${pattern.count} ocurrencias)\n`;
        });
      }
    }
    
    // Add to forensics log
    this.addForensicsLogEntry('Analizador', analysisText, 'info');
  }

  viewAnalysisReports() {
    this.showNotification('Visualización de reportes en desarrollo', 'info');
    this.addForensicsLogEntry('Analizador', 'Visualización de reportes solicitada', 'info');
  }

  // ===== SYSTEM ANALYSIS FUNCTIONALITY =====
  
  async fullSystemAnalysis() {
    try {
      this.showNotification('Iniciando análisis completo del sistema...', 'info');
      this.addForensicsLogEntry('Sistema', 'Iniciando análisis completo...', 'info');
      
      // Update button state
      this.updateSystemAnalysisButtonState(true);
      
      const result = await window.electronAPI.fullSystemAnalysis();
      
      if (result.success) {
        this.displaySystemAnalysisResults(result.analysis);
        this.addForensicsLogEntry('Sistema', `Análisis completado en ${result.duration}ms`, 'success');
        this.showNotification('Análisis completo del sistema finalizado', 'success');
      } else {
        this.addForensicsLogEntry('Sistema', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error en análisis completo:', error);
      this.addForensicsLogEntry('Sistema', `Error: ${error.message}`, 'error');
      this.showNotification('Error en análisis completo del sistema', 'error');
    } finally {
      this.updateSystemAnalysisButtonState(false);
    }
  }


  async generateSystemReport() {
    try {
      this.showNotification('Generando reporte del sistema...', 'info');
      this.addForensicsLogEntry('Sistema', 'Generando reporte...', 'info');
      
      // Update button state
      this.updateSystemAnalysisButtonState(true);
      
      const result = await window.electronAPI.generateSystemReport();
      
      if (result.success) {
        this.displaySystemAnalysisResults(result.report.system);
        this.addForensicsLogEntry('Sistema', `Reporte generado: ${result.fileName}`, 'success');
        this.showNotification(`Reporte guardado en Escritorio: ${result.fileName}`, 'success');
        
        // Show detailed information section
        this.showDetailedSystemInfo();
      } else {
        this.addForensicsLogEntry('Sistema', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error generando reporte:', error);
      this.addForensicsLogEntry('Sistema', `Error: ${error.message}`, 'error');
      this.showNotification('Error generando reporte del sistema', 'error');
    } finally {
      this.updateSystemAnalysisButtonState(false);
    }
  }

  displaySystemAnalysisResults(analysis) {
    try {
      // Update system status
      this.updateSystemStatus(analysis);
      
      // Update system information
      this.updateSystemInformation(analysis.system);
      
      // Update detailed system information
      this.updateDetailedSystemInformation(analysis.system);
      
      // Update analysis indicators
      this.updateAnalysisIndicators(analysis);
      
      // Update last analysis time
      this.updateLastAnalysisTime();
      
      // Show detailed information section
      this.showDetailedSystemInfo();
      
    } catch (error) {
      console.error('Error displaying system analysis results:', error);
    }
  }

  updateSystemStatus(analysis) {
    const statusElement = document.getElementById('system-status');
    const infoElement = document.getElementById('system-info');
    
    if (!statusElement || !infoElement) return;
    
    // Determine system status based on analysis
    let status = 'Seguro';
    let statusClass = 'bg-green-100 text-green-700';
    let systemInfo = '';
    
    if (analysis.system) {
      const platform = analysis.system.platform || 'Unknown';
      const release = analysis.system.release || 'Unknown';
      systemInfo = `${platform} ${release}`;
    }
    
    // Check for security issues
    if (analysis.security) {
      if (analysis.security.firewall && analysis.security.firewall.status === 'disabled') {
        status = 'Advertencia';
        statusClass = 'bg-yellow-100 text-yellow-700';
      }
      
      if (analysis.security.antivirus && analysis.security.antivirus.length === 0) {
        status = 'Riesgo';
        statusClass = 'bg-red-100 text-red-700';
      }
    }
    
    statusElement.textContent = status;
    statusElement.className = `text-xs px-2 py-1 ${statusClass} rounded-full`;
    infoElement.textContent = systemInfo || 'Información del sistema obtenida';
  }

  updateSystemInformation(systemInfo) {
    if (!systemInfo) return;
    
    // Update system version info
    const versionElement = document.getElementById('system-version-info');
    if (versionElement) {
      versionElement.textContent = systemInfo.release || 'No disponible';
    }
    
    // Update platform info
    const platformElement = document.getElementById('system-platform-info');
    if (platformElement) {
      const platform = systemInfo.platform || 'Unknown';
      const arch = systemInfo.arch || 'Unknown';
      platformElement.textContent = `${platform} ${arch}`;
    }
  }

  updateAnalysisIndicators(analysis) {
    // Update process indicator
    const processesIcon = document.getElementById('processes-icon');
    if (processesIcon && analysis.processes) {
      processesIcon.className = 'fas fa-check-circle text-green-500 text-xs';
    }
    
    // Update network indicator
    const networkIcon = document.getElementById('network-icon');
    if (networkIcon && analysis.network) {
      networkIcon.className = 'fas fa-check-circle text-green-500 text-xs';
    }
    
    // Update filesystem indicator
    const tempfilesIcon = document.getElementById('tempfiles-icon');
    if (tempfilesIcon && analysis.filesystem) {
      tempfilesIcon.className = 'fas fa-check-circle text-green-500 text-xs';
    }
    
    // Update registry indicator (always show as checked for Windows)
    const registryIcon = document.getElementById('registry-icon');
    if (registryIcon) {
      registryIcon.className = 'fas fa-check-circle text-green-500 text-xs';
    }
  }

  updateLastAnalysisTime() {
    const lastAnalysisElement = document.getElementById('system-last-analysis');
    if (lastAnalysisElement) {
      const now = new Date();
      lastAnalysisElement.textContent = now.toLocaleTimeString('es-ES', { 
        hour: '2-digit', 
        minute: '2-digit' 
      });
    }
  }

  updateSystemAnalysisButtonState(isAnalyzing) {
    const buttons = document.querySelectorAll('[data-action="full-system-analysis"], [data-action="system-report"]');
    buttons.forEach(button => {
      button.disabled = isAnalyzing;
      if (isAnalyzing) {
        button.classList.add('opacity-50', 'cursor-not-allowed');
      } else {
        button.classList.remove('opacity-50', 'cursor-not-allowed');
      }
    });
  }

  updateDetailedSystemInformation(systemInfo) {
    if (!systemInfo) return;
    
    // Update OS Information
    this.updateOSInformation(systemInfo);
    
    // Update Hardware Information
    this.updateHardwareInformation(systemInfo);
    
    // Update Network Information
    this.updateNetworkInformation(systemInfo);
    
    // Update Storage Information
    this.updateStorageInformation(systemInfo);
  }

  updateOSInformation(systemInfo) {
    // OS Name
    const osNameElement = document.getElementById('os-name');
    if (osNameElement && systemInfo.windowsInfo?.version?.caption) {
      osNameElement.textContent = systemInfo.windowsInfo.version.caption;
    } else if (osNameElement) {
      osNameElement.textContent = `${systemInfo.platform} ${systemInfo.release}`;
    }
    
    // OS Version
    const osVersionElement = document.getElementById('os-version');
    if (osVersionElement && systemInfo.windowsInfo?.version?.version) {
      osVersionElement.textContent = systemInfo.windowsInfo.version.version;
    } else if (osVersionElement) {
      osVersionElement.textContent = systemInfo.release;
    }
    
    // Architecture
    const osArchElement = document.getElementById('os-arch');
    if (osArchElement) {
      osArchElement.textContent = systemInfo.arch;
    }
    
    // Hostname
    const osHostnameElement = document.getElementById('os-hostname');
    if (osHostnameElement) {
      osHostnameElement.textContent = systemInfo.hostname;
    }
  }

  updateHardwareInformation(systemInfo) {
    // CPU Model
    const cpuModelElement = document.getElementById('cpu-model');
    if (cpuModelElement && systemInfo.cpu?.model) {
      cpuModelElement.textContent = systemInfo.cpu.model;
    }
    
    // CPU Cores
    const cpuCoresElement = document.getElementById('cpu-cores');
    if (cpuCoresElement && systemInfo.cpu?.cores) {
      cpuCoresElement.textContent = `${systemInfo.cpu.cores} núcleos`;
    }
    
    // Memory Total
    const memoryTotalElement = document.getElementById('memory-total');
    if (memoryTotalElement && systemInfo.memory?.total) {
      memoryTotalElement.textContent = this.formatBytes(systemInfo.memory.total);
    }
    
    // Memory Free
    const memoryFreeElement = document.getElementById('memory-free');
    if (memoryFreeElement && systemInfo.memory?.free) {
      memoryFreeElement.textContent = this.formatBytes(systemInfo.memory.free);
    }
  }

  updateNetworkInformation(systemInfo) {
    // WiFi Status
    const wifiStatusElement = document.getElementById('wifi-status');
    if (wifiStatusElement) {
      const wifiInfo = systemInfo.windowsInfo?.wifi;
      if (wifiInfo?.currentConnection?.ssid) {
        wifiStatusElement.textContent = 'Conectado';
        wifiStatusElement.className = 'font-medium text-green-600';
      } else {
        wifiStatusElement.textContent = 'Desconectado';
        wifiStatusElement.className = 'font-medium text-red-600';
      }
    }
    
    // WiFi SSID
    const wifiSSIDElement = document.getElementById('wifi-ssid');
    if (wifiSSIDElement && systemInfo.windowsInfo?.wifi?.currentConnection?.ssid) {
      wifiSSIDElement.textContent = systemInfo.windowsInfo.wifi.currentConnection.ssid;
    } else if (wifiSSIDElement) {
      wifiSSIDElement.textContent = 'No disponible';
    }
    
    // WiFi Security
    const wifiSecurityElement = document.getElementById('wifi-security');
    if (wifiSecurityElement && systemInfo.windowsInfo?.wifi?.currentConnection?.authentication) {
      const auth = systemInfo.windowsInfo.wifi.currentConnection.authentication;
      wifiSecurityElement.textContent = auth;
      wifiSecurityElement.className = auth.includes('WPA') || auth.includes('WPA2') || auth.includes('WPA3') ? 
        'font-medium text-green-600' : 'font-medium text-yellow-600';
    } else if (wifiSecurityElement) {
      wifiSecurityElement.textContent = 'No disponible';
    }
    
    // WiFi Signal
    const wifiSignalElement = document.getElementById('wifi-signal');
    if (wifiSignalElement && systemInfo.windowsInfo?.wifi?.currentConnection?.signal) {
      wifiSignalElement.textContent = systemInfo.windowsInfo.wifi.currentConnection.signal;
    } else if (wifiSignalElement) {
      wifiSignalElement.textContent = 'No disponible';
    }
  }

  updateStorageInformation(systemInfo) {
    const diskInfoElement = document.getElementById('disk-info');
    if (!diskInfoElement) return;
    
    const disks = systemInfo.windowsInfo?.disks;
    if (disks && Array.isArray(disks)) {
      diskInfoElement.innerHTML = '';
      disks.forEach(disk => {
        if (disk.caption && disk.size > 0) {
          const diskDiv = document.createElement('div');
          diskDiv.className = 'flex justify-between items-center';
          
          const totalGB = this.formatBytes(disk.size);
          const freeGB = this.formatBytes(disk.freeSpace);
          const usedGB = this.formatBytes(disk.size - disk.freeSpace);
          const usagePercent = ((disk.size - disk.freeSpace) / disk.size * 100).toFixed(1);
          
          diskDiv.innerHTML = `
            <span class="text-gray-600">${disk.caption} (${disk.volumeName || 'Sin nombre'}):</span>
            <span class="font-medium">${usedGB} / ${totalGB} (${usagePercent}% usado)</span>
          `;
          
          diskInfoElement.appendChild(diskDiv);
        }
      });
    } else {
      diskInfoElement.innerHTML = '<div class="text-gray-500">Información de disco no disponible</div>';
    }
  }

  showDetailedSystemInfo() {
    const detailedInfoElement = document.getElementById('detailed-system-info');
    if (detailedInfoElement) {
      detailedInfoElement.classList.remove('hidden');
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // ===== ANTIVIRUS TESTING FUNCTIONALITY =====
  
  async generateTestFiles() {
    try {
      this.showNotification('Generando archivos de prueba seguros...', 'info');
      this.addForensicsLogEntry('Pruebas', 'Generando archivos de prueba...', 'info');
      
      const result = await window.electronAPI.generateTestFiles();
      
      if (result.success) {
        this.addForensicsLogEntry('Pruebas', `Archivos de prueba generados: ${result.files.length} archivos`, 'success');
        this.showNotification(`Archivos de prueba creados en OneDrive/Escritorio/Antivirus_Test_Files`, 'success');
        
        // Display test files information
        this.displayTestFilesInfo(result.files);
      } else {
        this.addForensicsLogEntry('Pruebas', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error generando archivos de prueba:', error);
      this.addForensicsLogEntry('Pruebas', `Error: ${error.message}`, 'error');
      this.showNotification('Error generando archivos de prueba', 'error');
    }
  }

  async testEicarDetection() {
    try {
      this.showNotification('Probando detección EICAR...', 'info');
      this.addForensicsLogEntry('Pruebas', 'Iniciando prueba EICAR...', 'info');
      
      const result = await window.electronAPI.testEicarDetection();
      
      if (result.detected) {
        this.addForensicsLogEntry('Pruebas', '✅ EICAR detectado correctamente', 'success');
        this.showNotification('✅ EICAR detectado - Antivirus funcionando correctamente', 'success');
      } else {
        this.addForensicsLogEntry('Pruebas', '⚠️ EICAR no detectado', 'warning');
        this.showNotification('⚠️ EICAR no detectado - Revisar configuración del antivirus', 'warning');
      }
      
      // Display detailed results
      this.displayEicarTestResults(result);
    } catch (error) {
      console.error('Error probando EICAR:', error);
      this.addForensicsLogEntry('Pruebas', `Error: ${error.message}`, 'error');
      this.showNotification('Error probando detección EICAR', 'error');
    }
  }

  displayTestFilesInfo(files) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    // Add header
    const headerDiv = document.createElement('div');
    headerDiv.className = 'p-3 bg-yellow-50 rounded-lg border border-yellow-200 mb-2';
    headerDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-yellow-800 mb-2">📁 Archivos de Prueba Generados</h4>
      <p class="text-xs text-yellow-700 mb-2">Ubicación: OneDrive/Escritorio/Antivirus_Test_Files/</p>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', headerDiv);
    } else {
      logDisplay.insertBefore(headerDiv, logDisplay.firstChild);
    }

    // Add file details
    files.forEach(file => {
      const fileDiv = document.createElement('div');
      fileDiv.className = 'p-2 bg-white rounded border border-gray-200 mb-1';
      fileDiv.innerHTML = `
        <div class="flex justify-between items-center">
          <div>
            <span class="text-sm font-medium text-gray-800">${file.name}</span>
            <span class="text-xs text-gray-500 ml-2">(${file.type})</span>
          </div>
          <span class="text-xs px-2 py-1 bg-green-100 text-green-700 rounded-full">Seguro</span>
        </div>
        <p class="text-xs text-gray-600 mt-1">${file.description}</p>
      `;
      headerDiv.appendChild(fileDiv);
    });
  }

  displayEicarTestResults(result) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = `p-3 rounded-lg border mb-2 ${result.detected ? 'bg-green-50 border-green-200' : 'bg-yellow-50 border-yellow-200'}`;
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold ${result.detected ? 'text-green-800' : 'text-yellow-800'} mb-2">
        ${result.detected ? '✅ Prueba EICAR Exitosa' : '⚠️ Prueba EICAR Fallida'}
      </h4>
      <p class="text-xs ${result.detected ? 'text-green-700' : 'text-yellow-700'} mb-2">${result.details || result.message || 'Test completed'}</p>
      ${result.detected ? 
        '<p class="text-xs text-green-600">El antivirus detectó correctamente el archivo EICAR de prueba.</p>' :
        '<p class="text-xs text-yellow-600">El antivirus no detectó el archivo EICAR. Esto puede indicar un problema de configuración.</p>'
      }
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }

  async generateAdvancedTestFiles() {
    try {
      this.showNotification('Generando archivos de prueba avanzados...', 'info');
      this.addForensicsLogEntry('Pruebas', 'Generando archivos de prueba avanzados...', 'info');
      
      const result = await window.electronAPI.generateAdvancedTestFiles();
      
      if (result.success) {
        this.addForensicsLogEntry('Pruebas', `Archivos avanzados generados: ${result.files.length} archivos`, 'success');
        this.showNotification(`Archivos avanzados creados - Más propensos a ser detectados`, 'success');
        
        // Display advanced test files information
        this.displayAdvancedTestFilesInfo(result.files);
      } else {
        this.addForensicsLogEntry('Pruebas', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error generando archivos avanzados:', error);
      this.addForensicsLogEntry('Pruebas', `Error: ${error.message}`, 'error');
      this.showNotification('Error generando archivos de prueba avanzados', 'error');
    }
  }

  displayAdvancedTestFilesInfo(files) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    // Add header
    const headerDiv = document.createElement('div');
    headerDiv.className = 'p-3 bg-red-50 rounded-lg border border-red-200 mb-2';
    headerDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-red-800 mb-2">⚠️ Archivos de Prueba Avanzados</h4>
      <p class="text-xs text-red-700 mb-2">Ubicación: OneDrive/Escritorio/Antivirus_Test_Files/</p>
      <p class="text-xs text-red-600 mb-2">Estos archivos tienen mayor probabilidad de ser detectados por antivirus</p>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', headerDiv);
    } else {
      logDisplay.insertBefore(headerDiv, logDisplay.firstChild);
    }

    // Add file details
    files.forEach(file => {
      const fileDiv = document.createElement('div');
      fileDiv.className = 'p-2 bg-white rounded border border-red-200 mb-1';
      fileDiv.innerHTML = `
        <div class="flex justify-between items-center">
          <div>
            <span class="text-sm font-medium text-gray-800">${file.name}</span>
            <span class="text-xs text-gray-500 ml-2">(${file.type})</span>
          </div>
          <span class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded-full">Alto Riesgo</span>
        </div>
        <p class="text-xs text-gray-600 mt-1">${file.description}</p>
      `;
      headerDiv.appendChild(fileDiv);
    });
  }

  async generateAggressiveTestFiles() {
    try {
      this.showNotification('Generando pruebas agresivas...', 'info');
      this.addForensicsLogEntry('Pruebas', 'Generando pruebas agresivas...', 'info');
      
      const result = await window.electronAPI.generateAggressiveTestFiles();
      
      if (result.success) {
        this.addForensicsLogEntry('Pruebas', `Pruebas agresivas generadas: ${result.files.length} archivos`, 'success');
        this.showNotification(`Pruebas agresivas creadas - MÁXIMA probabilidad de detección`, 'success');
        
        // Display aggressive test files information
        this.displayAggressiveTestFilesInfo(result.files);
      } else {
        this.addForensicsLogEntry('Pruebas', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error generando pruebas agresivas:', error);
      this.addForensicsLogEntry('Pruebas', `Error: ${error.message}`, 'error');
      this.showNotification('Error generando pruebas agresivas', 'error');
    }
  }

  displayAggressiveTestFilesInfo(files) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    // Add header
    const headerDiv = document.createElement('div');
    headerDiv.className = 'p-3 bg-purple-50 rounded-lg border border-purple-200 mb-2';
    headerDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-purple-800 mb-2">💥 Pruebas Agresivas</h4>
      <p class="text-xs text-purple-700 mb-2">Ubicación: OneDrive/Escritorio/Antivirus_Test_Files/</p>
      <p class="text-xs text-purple-600 mb-2">⚠️ Estos archivos tienen MÁXIMA probabilidad de ser detectados</p>
      <p class="text-xs text-purple-500 mb-2">Incluyen headers ejecutables, scripts de sistema y operaciones sospechosas</p>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', headerDiv);
    } else {
      logDisplay.insertBefore(headerDiv, logDisplay.firstChild);
    }

    // Add file details
    files.forEach(file => {
      const fileDiv = document.createElement('div');
      fileDiv.className = 'p-2 bg-white rounded border border-purple-200 mb-1';
      fileDiv.innerHTML = `
        <div class="flex justify-between items-center">
          <div>
            <span class="text-sm font-medium text-gray-800">${file.name}</span>
            <span class="text-xs text-gray-500 ml-2">(${file.type})</span>
          </div>
          <span class="text-xs px-2 py-1 bg-purple-100 text-purple-700 rounded-full">MÁXIMO RIESGO</span>
        </div>
        <p class="text-xs text-gray-600 mt-1">${file.description}</p>
      `;
      headerDiv.appendChild(fileDiv);
    });
  }

  async testRealAntivirusDetection() {
    try {
      this.showNotification('Iniciando prueba real de antivirus...', 'info');
      this.addForensicsLogEntry('Pruebas', 'Iniciando prueba real de antivirus...', 'info');
      
      const result = await window.electronAPI.testRealAntivirusDetection();
      
      if (result.success) {
        this.displayRealAntivirusTestResults(result.result);
        this.addForensicsLogEntry('Pruebas', 'Prueba real completada', 'success');
        this.showNotification('Prueba real de antivirus completada', 'success');
      } else {
        this.addForensicsLogEntry('Pruebas', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error en prueba real:', error);
      this.addForensicsLogEntry('Pruebas', `Error: ${error.message}`, 'error');
      this.showNotification('Error en prueba real de antivirus', 'error');
    }
  }

  displayRealAntivirusTestResults(results) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = 'p-4 bg-gray-50 rounded-lg border border-gray-200 mb-2';
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-gray-800 mb-3">🛡️ Resultados de Prueba Real de Antivirus</h4>
      
      <div class="space-y-3">
        <!-- EICAR Test Results -->
        <div class="p-3 rounded-lg ${results.eicarTest.detected ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium ${results.eicarTest.detected ? 'text-green-800' : 'text-red-800'}">Prueba EICAR</span>
            <span class="text-xs px-2 py-1 rounded-full ${results.eicarTest.detected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">
              ${results.eicarTest.detected ? '✅ Detectado' : '❌ No Detectado'}
            </span>
          </div>
          <p class="text-xs ${results.eicarTest.detected ? 'text-green-700' : 'text-red-700'}">
            ${results.eicarTest.detected ? 'El antivirus detectó y bloqueó el archivo EICAR' : 'El antivirus NO detectó el archivo EICAR'}
          </p>
        </div>
        
        <!-- Real-time Protection Results -->
        <div class="p-3 rounded-lg ${results.realTimeTest.detected ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium ${results.realTimeTest.detected ? 'text-green-800' : 'text-red-800'}">Protección en Tiempo Real</span>
            <span class="text-xs px-2 py-1 rounded-full ${results.realTimeTest.detected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">
              ${results.realTimeTest.detected ? '✅ Bloqueado' : '❌ No Bloqueado'}
            </span>
          </div>
          <p class="text-xs ${results.realTimeTest.detected ? 'text-green-700' : 'text-red-700'}">
            ${results.realTimeTest.detected ? 'El antivirus bloqueó la ejecución del script sospechoso' : 'El antivirus NO bloqueó la ejecución del script'}
          </p>
        </div>
        
        <!-- Recommendations -->
        <div class="p-3 bg-blue-50 rounded-lg border border-blue-200">
          <h5 class="text-sm font-medium text-blue-800 mb-2">📋 Recomendaciones:</h5>
          <ul class="text-xs text-blue-700 space-y-1">
            ${results.recommendations.map(rec => `<li>• ${rec}</li>`).join('')}
          </ul>
        </div>
      </div>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }

  async diagnoseAntivirusStatus() {
    try {
      this.showNotification('Diagnosticando estado del antivirus...', 'info');
      this.addForensicsLogEntry('Diagnóstico', 'Iniciando diagnóstico del antivirus...', 'info');
      
      const result = await window.electronAPI.diagnoseAntivirusStatus();
      
      if (result.success) {
        this.displayAntivirusDiagnosis(result.result);
        this.addForensicsLogEntry('Diagnóstico', 'Diagnóstico completado', 'success');
        this.showNotification('Diagnóstico del antivirus completado', 'success');
      } else {
        this.addForensicsLogEntry('Diagnóstico', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error en diagnóstico:', error);
      this.addForensicsLogEntry('Diagnóstico', `Error: ${error.message}`, 'error');
      this.showNotification('Error en diagnóstico del antivirus', 'error');
    }
  }

  displayAntivirusDiagnosis(diagnosis) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = 'p-4 bg-blue-50 rounded-lg border border-blue-200 mb-2';
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-blue-800 mb-3">🔍 Diagnóstico del Antivirus</h4>
      
      <div class="space-y-3">
        <!-- Windows Defender Status -->
        <div class="p-3 rounded-lg ${diagnosis.windowsDefender.enabled ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium ${diagnosis.windowsDefender.enabled ? 'text-green-800' : 'text-red-800'}">Windows Defender</span>
            <span class="text-xs px-2 py-1 rounded-full ${diagnosis.windowsDefender.enabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">
              ${diagnosis.windowsDefender.enabled ? '✅ Habilitado' : '❌ Deshabilitado'}
            </span>
          </div>
          <p class="text-xs ${diagnosis.windowsDefender.enabled ? 'text-green-700' : 'text-red-700'}">
            ${diagnosis.windowsDefender.enabled ? 
              (diagnosis.windowsDefender.realTimeEnabled ? 'Protección en tiempo real habilitada' : 'Protección en tiempo real deshabilitada') :
              'Windows Defender está deshabilitado'
            }
          </p>
        </div>
        
        <!-- Antivirus Processes -->
        <div class="p-3 bg-gray-50 rounded-lg border border-gray-200">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium text-gray-800">Procesos de Antivirus Detectados</span>
            <span class="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded-full">
              ${diagnosis.antivirusProcesses.length} proceso${diagnosis.antivirusProcesses.length !== 1 ? 's' : ''}
            </span>
          </div>
          ${diagnosis.antivirusProcesses.length > 0 ? 
            `<p class="text-xs text-gray-700">Procesos: ${diagnosis.antivirusProcesses.join(', ')}</p>` :
            '<p class="text-xs text-gray-600">No se detectaron procesos de antivirus de terceros</p>'
          }
        </div>
        
        <!-- Recommendations -->
        <div class="p-3 bg-yellow-50 rounded-lg border border-yellow-200">
          <h5 class="text-sm font-medium text-yellow-800 mb-2">📋 Recomendaciones:</h5>
          <ul class="text-xs text-yellow-700 space-y-1">
            ${diagnosis.recommendations.map(rec => `<li>• ${rec}</li>`).join('')}
          </ul>
        </div>
        
        <!-- Manual Steps -->
        <div class="p-3 bg-purple-50 rounded-lg border border-purple-200">
          <h5 class="text-sm font-medium text-purple-800 mb-2">🛠️ Pasos Manuales Requeridos:</h5>
          <ul class="text-xs text-purple-700 space-y-1">
            <li>• Abrir Windows Security (Windows + I → Update & Security → Windows Security)</li>
            <li>• Ir a "Virus & threat protection"</li>
            <li>• Verificar que "Real-time protection" esté habilitado</li>
            <li>• Verificar que "Cloud-delivered protection" esté habilitado</li>
            <li>• Ejecutar "Quick scan" para verificar funcionamiento</li>
          </ul>
        </div>
      </div>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }

  async generateRealMalwareTests() {
    try {
      this.showNotification('Generando pruebas con firmas reales...', 'info');
      this.addForensicsLogEntry('Pruebas', 'Generando pruebas con firmas reales...', 'info');
      
      const result = await window.electronAPI.generateRealMalwareTests();
      
      if (result.success) {
        this.displayRealMalwareTestResults(result.result);
        this.addForensicsLogEntry('Pruebas', 'Pruebas con firmas reales completadas', 'success');
        this.showNotification('Pruebas con firmas reales completadas', 'success');
      } else {
        this.addForensicsLogEntry('Pruebas', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error en pruebas con firmas reales:', error);
      this.addForensicsLogEntry('Pruebas', `Error: ${error.message}`, 'error');
      this.showNotification('Error en pruebas con firmas reales', 'error');
    }
  }

  displayRealMalwareTestResults(results) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = 'p-4 bg-emerald-50 rounded-lg border border-emerald-200 mb-2';
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-emerald-800 mb-3">🦠 Pruebas con Firmas Reales</h4>
      
      <div class="space-y-3">
        <!-- Files Created -->
        <div class="p-3 bg-white rounded-lg border border-emerald-200">
          <div class="flex items-center justify-between mb-2">
            <span class="text-sm font-medium text-emerald-800">Archivos Creados</span>
            <span class="text-xs px-2 py-1 bg-emerald-100 text-emerald-700 rounded-full">
              ${results.filesCreated.length} archivo${results.filesCreated.length !== 1 ? 's' : ''}
            </span>
          </div>
          <div class="text-xs text-emerald-700">
            ${results.filesCreated.map(file => `<div>• ${file}</div>`).join('')}
          </div>
        </div>
        
        <!-- Test Results -->
        <div class="space-y-2">
          ${results.testsPerformed.map(test => `
            <div class="p-3 rounded-lg ${test.result === 'DETECTED' || test.result === 'BLOCKED' ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}">
              <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-medium ${test.result === 'DETECTED' || test.result === 'BLOCKED' ? 'text-green-800' : 'text-red-800'}">${test.test}</span>
                <span class="text-xs px-2 py-1 rounded-full ${test.result === 'DETECTED' || test.result === 'BLOCKED' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">
                  ${test.result === 'DETECTED' || test.result === 'BLOCKED' ? '✅ ' + test.result : '❌ ' + test.result}
                </span>
              </div>
              <p class="text-xs ${test.result === 'DETECTED' || test.result === 'BLOCKED' ? 'text-green-700' : 'text-red-700'}">${test.details}</p>
            </div>
          `).join('')}
        </div>
        
        <!-- Recommendations -->
        <div class="p-3 bg-yellow-50 rounded-lg border border-yellow-200">
          <h5 class="text-sm font-medium text-yellow-800 mb-2">📋 Recomendaciones:</h5>
          <ul class="text-xs text-yellow-700 space-y-1">
            ${results.recommendations.map(rec => `<li>• ${rec}</li>`).join('')}
          </ul>
        </div>
        
        <!-- Important Note -->
        <div class="p-3 bg-blue-50 rounded-lg border border-blue-200">
          <h5 class="text-sm font-medium text-blue-800 mb-2">ℹ️ Información Importante:</h5>
          <p class="text-xs text-blue-700">
            Estas pruebas utilizan firmas y patrones reales de malware pero son completamente seguras. 
            Si tu antivirus no detecta estos archivos, puede indicar problemas de configuración.
          </p>
        </div>
      </div>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }

  async comprehensiveAntivirusDiagnostic() {
    try {
      this.showNotification('Ejecutando diagnóstico completo del antivirus...', 'info');
      this.addForensicsLogEntry('Diagnóstico', 'Iniciando diagnóstico completo del antivirus...', 'info');
      
      const result = await window.electronAPI.comprehensiveAntivirusDiagnostic();
      
      if (result.success) {
        this.displayComprehensiveDiagnostic(result.result);
        this.addForensicsLogEntry('Diagnóstico', 'Diagnóstico completo finalizado', 'success');
        this.showNotification('Diagnóstico completo finalizado', 'success');
      } else {
        this.addForensicsLogEntry('Diagnóstico', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error en diagnóstico completo:', error);
      this.addForensicsLogEntry('Diagnóstico', `Error: ${error.message}`, 'error');
      this.showNotification('Error en diagnóstico completo', 'error');
    }
  }

  async deleteThreats() {
    try {
      this.showNotification('Eliminando amenazas detectadas...', 'info');
      this.addForensicsLogEntry('Eliminación', 'Iniciando eliminación de amenazas...', 'info');
      
      const result = await window.electronAPI.deleteThreats();
      
      if (result.success) {
        this.addForensicsLogEntry('Eliminación', result.message, 'success');
        this.showNotification(result.message, 'success');
        
        // Display detailed results
        this.displayThreatDeletionResults(result.details);
        
        // Update antivirus stats
        this.updateAntivirusStats({
          threatsFound: 0,
          filesScanned: 0
        });
      } else {
        this.addForensicsLogEntry('Eliminación', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error eliminando amenazas:', error);
      this.addForensicsLogEntry('Eliminación', `Error: ${error.message}`, 'error');
      this.showNotification('Error eliminando amenazas', 'error');
    }
  }

  async clearThreatHistory() {
    try {
      this.showNotification('Limpiando historial de amenazas...', 'info');
      this.addForensicsLogEntry('Limpieza', 'Iniciando limpieza del historial de amenazas...', 'info');
      
      const result = await window.electronAPI.clearThreatHistory();
      
      if (result.success) {
        this.addForensicsLogEntry('Limpieza', result.message, 'success');
        this.showNotification(result.message, 'success');
        
        // Update the UI with new stats
        this.updateAntivirusStats({
          threatsFound: result.newStats.threatsFound,
          filesScanned: result.newStats.filesScanned
        });
        
        // Show detailed results
        this.displayThreatHistoryClearedResults(result.newStats);
      } else {
        this.addForensicsLogEntry('Limpieza', `Error: ${result.message}`, 'error');
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error limpiando historial:', error);
      this.addForensicsLogEntry('Limpieza', `Error: ${error.message}`, 'error');
      this.showNotification('Error limpiando historial', 'error');
    }
  }

  displayThreatDeletionResults(details) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = 'p-4 bg-green-50 rounded-lg border border-green-200 mb-2';
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-green-800 mb-3">🗑️ Resultados de Eliminación de Amenazas</h4>
      
      <div class="space-y-3">
        <!-- Summary -->
        <div class="p-3 bg-white rounded-lg border border-gray-200">
          <h5 class="text-sm font-medium text-gray-800 mb-2">📊 Resumen:</h5>
          <div class="text-xs text-gray-700 space-y-1">
            <div>• Archivos eliminados: <span class="font-semibold text-green-600">${details.totalDeleted}</span></div>
            ${details.errors.length > 0 ? `<div>• Errores: <span class="font-semibold text-red-600">${details.errors.length}</span></div>` : ''}
          </div>
        </div>
        
        <!-- Deleted Files -->
        ${details.deletedFiles.length > 0 ? `
          <div class="p-3 bg-white rounded-lg border border-gray-200">
            <h5 class="text-sm font-medium text-gray-800 mb-2">✅ Archivos Eliminados:</h5>
            <div class="text-xs text-gray-700 space-y-1 max-h-32 overflow-y-auto">
              ${details.deletedFiles.map(file => `<div>• ${file}</div>`).join('')}
            </div>
          </div>
        ` : ''}
        
        <!-- Errors -->
        ${details.errors.length > 0 ? `
          <div class="p-3 bg-red-50 rounded-lg border border-red-200">
            <h5 class="text-sm font-medium text-red-800 mb-2">❌ Errores:</h5>
            <div class="text-xs text-red-700 space-y-1">
              ${details.errors.map(error => `<div>• ${error}</div>`).join('')}
            </div>
          </div>
        ` : ''}
        
        <!-- Info -->
        ${details.info ? `
          <div class="p-3 bg-blue-50 rounded-lg border border-blue-200">
            <h5 class="text-sm font-medium text-blue-800 mb-2">ℹ️ Información:</h5>
            <div class="text-xs text-blue-700">
              ${details.info}
            </div>
          </div>
        ` : ''}
      </div>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }

  displayComprehensiveDiagnostic(diagnostic) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = 'p-4 bg-red-50 rounded-lg border border-red-200 mb-2';
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-red-800 mb-3">🔍 Diagnóstico Completo del Antivirus</h4>
      
      <div class="space-y-3">
        <!-- Critical Issues -->
        ${diagnostic.criticalIssues.length > 0 ? `
          <div class="p-3 bg-red-100 rounded-lg border border-red-300">
            <h5 class="text-sm font-medium text-red-800 mb-2">🚨 Problemas Críticos:</h5>
            <ul class="text-xs text-red-700 space-y-1">
              ${diagnostic.criticalIssues.map(issue => `<li>• ${issue}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
        
        <!-- Windows Defender Status -->
        <div class="p-3 bg-white rounded-lg border border-gray-200">
          <h5 class="text-sm font-medium text-gray-800 mb-2">🛡️ Estado de Windows Defender:</h5>
          <div class="text-xs text-gray-700 space-y-1">
            <div>• Antivirus: ${diagnostic.windowsDefenderStatus.antivirusEnabled ? '✅ Habilitado' : '❌ Deshabilitado'}</div>
            <div>• Protección en Tiempo Real: ${diagnostic.windowsDefenderStatus.realTimeEnabled ? '✅ Habilitada' : '❌ Deshabilitada'}</div>
            <div>• Protección de Acceso: ${diagnostic.windowsDefenderStatus.onAccessEnabled ? '✅ Habilitada' : '❌ Deshabilitada'}</div>
            <div>• Protección en la Nube: ${diagnostic.windowsDefenderStatus.cloudEnabled ? '✅ Habilitada' : '❌ Deshabilitada'}</div>
          </div>
        </div>
        
        <!-- Service Status -->
        <div class="p-3 bg-white rounded-lg border border-gray-200">
          <h5 class="text-sm font-medium text-gray-800 mb-2">⚙️ Estado del Servicio:</h5>
          <div class="text-xs text-gray-700 space-y-1">
            <div>• Estado: ${diagnostic.serviceStatus.status === 'Running' ? '✅ Ejecutándose' : '❌ Detenido'}</div>
            <div>• Tipo de Inicio: ${diagnostic.serviceStatus.startType === 'Automatic' ? '✅ Automático' : '❌ Manual'}</div>
          </div>
        </div>
        
        <!-- Test Results -->
        <div class="p-3 bg-white rounded-lg border border-gray-200">
          <h5 class="text-sm font-medium text-gray-800 mb-2">🧪 Resultados de Pruebas EICAR:</h5>
          <div class="text-xs text-gray-700 space-y-1">
            ${Object.entries(diagnostic.testResults).map(([location, result]) => `
              <div class="flex justify-between items-center">
                <span>${location}:</span>
                <span class="${result.detected ? 'text-green-600' : 'text-red-600'}">
                  ${result.detected ? '✅ Detectado' : '❌ No Detectado'}
                </span>
              </div>
            `).join('')}
          </div>
        </div>
        
        <!-- Third-party Antivirus -->
        ${diagnostic.thirdPartyAntivirus.length > 0 ? `
          <div class="p-3 bg-yellow-50 rounded-lg border border-yellow-200">
            <h5 class="text-sm font-medium text-yellow-800 mb-2">⚠️ Antivirus de Terceros Detectado:</h5>
            <div class="text-xs text-yellow-700">
              ${diagnostic.thirdPartyAntivirus.map(av => `<div>• ${av}</div>`).join('')}
            </div>
          </div>
        ` : ''}
        
        <!-- Exclusions -->
        <div class="p-3 bg-white rounded-lg border border-gray-200">
          <h5 class="text-sm font-medium text-gray-800 mb-2">🚫 Exclusiones:</h5>
          <div class="text-xs text-gray-700">
            ${diagnostic.exclusions.paths || 'No se pudieron verificar las exclusiones'}
          </div>
        </div>
        
        <!-- Recommendations -->
        <div class="p-3 bg-blue-50 rounded-lg border border-blue-200">
          <h5 class="text-sm font-medium text-blue-800 mb-2">📋 Recomendaciones:</h5>
          <ul class="text-xs text-blue-700 space-y-1">
            ${diagnostic.recommendations.map(rec => `<li>• ${rec}</li>`).join('')}
          </ul>
        </div>
        
        <!-- Action Steps -->
        <div class="p-3 bg-purple-50 rounded-lg border border-purple-200">
          <h5 class="text-sm font-medium text-purple-800 mb-2">🛠️ Pasos de Acción:</h5>
          <ul class="text-xs text-purple-700 space-y-1">
            <li>• Abrir Windows Security (Windows + I → Update & Security → Windows Security)</li>
            <li>• Ir a "Virus & threat protection"</li>
            <li>• Verificar que todas las protecciones estén habilitadas</li>
            <li>• Revisar "Exclusions" y eliminar exclusiones innecesarias</li>
            <li>• Ejecutar "Quick scan" para verificar funcionamiento</li>
            <li>• Si persisten problemas, ejecutar "Windows Defender Offline scan"</li>
          </ul>
        </div>
      </div>
    `;
    
    // Insert after progress bar if exists, otherwise at the beginning
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }

  // ===== FORENSICS LOG MANAGEMENT =====
  
  addForensicsLogEntry(category, message, type = 'info') {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    // Limpiar mensaje de "no hay análisis" si existe
    if (logDisplay.innerHTML.includes('No hay análisis realizados')) {
      logDisplay.innerHTML = '';
    }

    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.className = 'mb-1 text-xs px-1 py-0.5 hover:bg-gray-700 rounded transition-colors duration-150';
    
    const typeColors = {
      info: 'text-blue-400',
      success: 'text-green-400',
      warning: 'text-yellow-400',
      error: 'text-red-400'
    };
    
    logEntry.innerHTML = `
      <span class="text-gray-500">[${timestamp}]</span> 
      <span class="font-semibold text-purple-400">[${category}]</span> 
      <span class="${typeColors[type] || 'text-gray-400'}">${message}</span>
    `;
    
    // Insert after the sticky progress container if it exists
    const progressContainer = logDisplay.querySelector('.sticky-progress-container');
    if (progressContainer) {
      logDisplay.insertBefore(logEntry, progressContainer.nextSibling);
    } else {
      logDisplay.appendChild(logEntry);
    }
    
    // Auto-scroll to bottom, but keep progress bar visible
    logDisplay.scrollTop = logDisplay.scrollHeight;
  }

  clearForensicsLog() {
    if (confirm('¿Limpiar el log de análisis forense?')) {
      const logDisplay = document.getElementById('forensics-log-display');
      if (logDisplay) {
        logDisplay.innerHTML = `
          <div class="text-center text-gray-400 py-8">
            <i class="fas fa-search text-4xl mb-4"></i>
            <p class="text-lg">No hay análisis realizados</p>
            <p class="text-sm">Inicia un análisis para ver los resultados aquí</p>
          </div>
        `;
      }
      this.showNotification('Log de análisis limpiado', 'success');
    }
  }

  async exportForensicsResults() {
    try {
      this.showNotification('Exportando resultados del análisis...', 'info');
      
      const logDisplay = document.getElementById('forensics-log-display');
      if (logDisplay) {
        const content = logDisplay.textContent;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `forensics_results_${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Resultados exportados correctamente', 'success');
      }
    } catch (error) {
      console.error('Error exportando resultados:', error);
      this.showNotification('Error exportando resultados', 'error');
    }
  }

  openForensicsSettings() {
    this.showNotification('Configuración forense en desarrollo', 'info');
  }

  displayThreatHistoryClearedResults(newStats) {
    const logDisplay = document.getElementById('forensics-log-display');
    if (!logDisplay) return;

    const resultDiv = document.createElement('div');
    resultDiv.className = 'p-4 bg-purple-50 rounded-lg border border-purple-200 mb-2';
    resultDiv.innerHTML = `
      <h4 class="text-sm font-semibold text-purple-800 mb-3">🧹 Historial de Amenazas Limpiado</h4>
      
      <div class="space-y-3">
        <div class="p-3 bg-white rounded-lg border border-gray-200">
          <h5 class="text-sm font-medium text-gray-800 mb-2">📊 Nuevas Estadísticas:</h5>
          <div class="text-xs text-gray-700 space-y-1">
            <div>• Amenazas encontradas: <span class="font-semibold text-purple-600">${newStats.threatsFound}</span></div>
            <div>• Archivos escaneados: <span class="font-semibold text-purple-600">${newStats.filesScanned}</span></div>
            <div>• Total de escaneos: <span class="font-semibold text-purple-600">${newStats.totalScans}</span></div>
          </div>
        </div>
        
        <div class="p-3 bg-purple-50 rounded-lg border border-purple-200">
          <h5 class="text-sm font-medium text-purple-800 mb-2">✅ Acción Completada:</h5>
          <div class="text-xs text-purple-700">
            Se ha limpiado completamente el historial de amenazas. Los contadores han sido reiniciados a cero.
          </div>
        </div>
      </div>
    `;
    
    const progressBar = logDisplay.querySelector('.sticky-progress-container');
    if (progressBar) {
      progressBar.insertAdjacentElement('afterend', resultDiv);
    } else {
      logDisplay.insertBefore(resultDiv, logDisplay.firstChild);
    }
  }
}

document.addEventListener('DOMContentLoaded', () => new CiberSegApp());
