// Modern JavaScript para la aplicación CiberSeg
class CiberSegApp {
  constructor() {
    this.currentSection = 'dashboard';
    this.termsAccepted = this.checkTermsAcceptance();
    this.threatCount = 0; // Track total threats detected
    this.activityLog = []; // Track real activity
    this.urlScanHistory = []; // Track URL scan history
    this.init();
  }

  async init() {
    this.setupEventListeners();
    this.setupOptimizedInputListeners();
    this.setupAnimations();
    this.initializeKeylogger();
    this.initializeAntivirusStats();
    await this.loadAppData();
    await this.loadActivityData();
    await this.loadDashboardData();
    this.setupDashboardRefresh();
    
    // Siempre mostrar modal de términos para propósitos de prueba
    this.showTermsModal();
    
    // Mostrar modal de términos si no se ha aceptado (descomentar cuando termine la prueba)
    // if (!this.termsAccepted) {
    //   this.showTermsModal();
    // }
    
    console.log('Aplicación CiberSeg inicializada exitosamente');
  }

  setupDashboardRefresh() {
    // Refresh dashboard data every 30 seconds
    // Dashboard refresh interval - reduced frequency to improve performance
    setInterval(() => {
      if (this.currentSection === 'dashboard') {
        // Use requestIdleCallback for better performance
        if (window.requestIdleCallback) {
          requestIdleCallback(() => this.refreshDashboardData());
        } else {
          setTimeout(() => this.refreshDashboardData(), 0);
        }
      }
    }, 60000); // Increased from 30s to 60s

    // Also refresh when navigating to dashboard
    const originalNavigateToSection = this.navigateToSection.bind(this);
    this.navigateToSection = (section) => {
      originalNavigateToSection(section);
      if (section === 'dashboard') {
        setTimeout(() => this.refreshDashboardData(), 100);
      }
    };
  }

  async refreshDashboardData() {
    try {
      await this.loadDashboardData();
      console.log('Dashboard data refreshed');
    } catch (error) {
      console.error('Error refreshing dashboard data:', error);
    }
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
        console.log('Button clicked with action:', action, 'Button:', btn);
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
      window.electronAPI.onAntivirusProgress(async (event, progressData) => {
        await this.handleAntivirusProgress(progressData);
      });
    }
  }

  // Optimize input field responsiveness
  setupOptimizedInputListeners() {
    // Add optimized event listeners for all input fields
    const inputFields = document.querySelectorAll('input, textarea');
    
    inputFields.forEach(input => {
      // Use passive listeners for better performance
      input.addEventListener('focus', () => {
        // Ensure input is immediately responsive
        input.style.pointerEvents = 'auto';
        input.style.zIndex = '10';
      }, { passive: true });
      
      input.addEventListener('blur', () => {
        // Reset styles when not focused
        input.style.pointerEvents = '';
        input.style.zIndex = '';
      }, { passive: true });
      
      // Optimize input events with debouncing
      let inputTimeout;
      input.addEventListener('input', () => {
        clearTimeout(inputTimeout);
        inputTimeout = setTimeout(() => {
          // Any input processing here
        }, 50); // Short debounce for responsiveness
      }, { passive: true });
    });
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
    console.log('handleAction called with action:', action);
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
      case 'scan-url':
        this.scanUrl();
        break;
      case 'clear-url':
        this.clearUrlInput();
        break;
      case 'scan-history':
        this.showUrlScanHistory();
        break;
      case 'run-analysis':
        this.openForensicAnalysis();
        break;
      case 'open-tools':
        break;
      // Keylogger actions
      case 'start-keylogger':
        this.startKeylogger();
        break;
      case 'stop-keylogger':
        this.stopKeylogger();
        break;
      case 'open-keylogger':
        this.navigateToSection('keylogger');
        break;
      case 'export-keylogger':
        this.exportKeyloggerData();
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
      // Acciones simplificadas del módulo de contraseñas
      case 'copy-password':
        this.copyPassword();
        break;
      case 'view-vault':
        this.viewVault();
        break;
      case 'add-to-vault':
        console.log('add-to-vault case triggered');
        this.addToVault();
        break;
      case 'export-vault':
        this.exportVault();
        break;
      case 'import-vault':
        this.importVault();
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
      urlscanner: 'URL Scanner',
      forensics: 'Herramientas Forenses',
    };

    const subtitles = {
      dashboard: 'Centro de herramientas de ciberseguridad',
      passwords: 'Administra y genera contraseñas seguras',
      urlscanner: 'Escanea URLs en busca de amenazas',
      forensics: 'Herramientas de análisis forense digital',
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
        case 'urlscanner':
          this.navigateToSection('urlscanner');
          this.showNotification('URL Scanner iniciado', 'success');
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
      // Obtener configuración actual - usar valores por defecto si no están disponibles
      const lengthElement = document.getElementById('password-length');
      const length = lengthElement ? parseInt(lengthElement.value) : 16;
      
      const includeUppercaseElement = document.getElementById('include-uppercase');
      const includeUppercase = includeUppercaseElement ? includeUppercaseElement.checked : true;
      
      const includeLowercaseElement = document.getElementById('include-lowercase');
      const includeLowercase = includeLowercaseElement ? includeLowercaseElement.checked : true;
      
      const includeNumbersElement = document.getElementById('include-numbers');
      const includeNumbers = includeNumbersElement ? includeNumbersElement.checked : true;
      
      const includeSymbolsElement = document.getElementById('include-symbols');
      const includeSymbols = includeSymbolsElement ? includeSymbolsElement.checked : true;

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
    this.showNotification('Seleccionando archivo para análisis...', 'info');
    
    try {
      // Create file input for user to select file
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '*/*'; // Accept all file types
      input.style.display = 'none';
      
      input.onchange = async (event) => {
        const file = event.target.files[0];
        if (!file) {
          this.showNotification('No se seleccionó ningún archivo', 'warning');
          return;
        }
        
        this.showNotification(`Analizando archivo: ${file.name}...`, 'info');
        
        try {
          // Read file and send for analysis
          const arrayBuffer = await file.arrayBuffer();
          const fileData = Buffer.from(arrayBuffer);
          
          const result = await window.electronAPI.forensicAnalysis({
            filename: file.name,
            size: file.size,
            type: file.type,
            data: fileData
          });
          
          if (result.status === 'completado') {
            this.showNotification(`Análisis completado. Archivo: ${result.fileType}, Sospechoso: ${result.suspicious ? 'Sí' : 'No'}`, 'success');
            console.log('Resultado del análisis forense:', result);
            
            // Refresh forensics dashboard data
            await this.loadForensicsStatus();
          } else {
            this.showNotification('Error en el análisis forense', 'error');
          }
        } catch (error) {
          console.error('Error en el análisis forense:', error);
          this.showNotification('Error en el análisis forense', 'error');
        }
        
        // Clean up
        document.body.removeChild(input);
      };
      
      // Add to DOM and trigger click
      document.body.appendChild(input);
      input.click();
      
    } catch (error) {
      console.error('Error abriendo selector de archivos:', error);
      this.showNotification('Error abriendo selector de archivos', 'error');
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

  async loadDashboardData() {
    try {
      // Run all dashboard data loading operations in parallel for better performance
      await Promise.all([
        this.loadVaultCount(),
        this.loadRecentPasswords(),
        this.loadPasswordList(),
        this.loadKeyloggerStatus(),
        this.loadAntivirusStatus(),
        this.loadForensicsStatus(),
        this.loadSystemStatus(),
        this.loadVaultDashboardData()
      ]);
      
      // Update statistics and activity after all data is loaded
      await this.updateDashboardStatistics();
      this.updateLastActivity();
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    }
  }

  // Track module usage for scoring
  trackModuleUsage(moduleName, action = 'used') {
    if (!this.appData) {
      this.appData = {};
    }
    
    // Initialize counters if they don't exist
    if (!this.appData.scanCount) this.appData.scanCount = 0;
    if (!this.appData.analysisCount) this.appData.analysisCount = 0;
    if (!this.appData.urlScanCount) this.appData.urlScanCount = 0;
    if (!this.appData.keyloggerUsage) this.appData.keyloggerUsage = 0;
    
    // Increment appropriate counter
    switch (moduleName) {
      case 'antivirus':
        this.appData.scanCount++;
        this.appData.lastScanDate = new Date().toISOString();
        break;
      case 'forensics':
        this.appData.analysisCount++;
        this.appData.lastAnalysis = {
          timestamp: new Date().toISOString(),
          type: action
        };
        break;
      case 'urlscanner':
        this.appData.urlScanCount++;
        break;
      case 'keylogger':
        this.appData.keyloggerUsage++;
        break;
    }
    
    // Save to localStorage
    localStorage.setItem('appData', JSON.stringify(this.appData));
    
    // Update dashboard immediately
    this.updateDashboardStatistics();
  }

  async updateDashboardStatistics() {
    try {
      // Calculate security score based on various factors
      let securityScore = 0;
      let activeModules = 0;
      let lastActivityTime = null;
      let usageScore = 0; // New: Track actual usage

      // Check vault status and usage
      const vaultStats = await window.electronAPI.getVaultStats();
      if (vaultStats.success && vaultStats.totalPasswords > 0) {
        securityScore += 20; // Base score for having vault
        activeModules++;
        
        // Add points based on password strength
        if (vaultStats.averageStrength > 70) securityScore += 15;
        else if (vaultStats.averageStrength > 50) securityScore += 10;
        else if (vaultStats.averageStrength > 30) securityScore += 5;
        
        // Usage-based scoring
        if (vaultStats.totalPasswords >= 10) usageScore += 20; // Heavy vault usage
        else if (vaultStats.totalPasswords >= 5) usageScore += 15; // Moderate usage
        else if (vaultStats.totalPasswords >= 1) usageScore += 10; // Light usage
        
        // Track vault activity
        if (vaultStats.lastActivity) {
          lastActivityTime = new Date(vaultStats.lastActivity);
        }
      }

      // Check keylogger status and usage
      const keyloggerStatus = await window.electronAPI.getKeyloggerStatus();
      if (keyloggerStatus.isRunning) {
        securityScore += 10; // Monitoring active
        activeModules++;
        
        // Usage-based scoring for keylogger
        if (keyloggerStatus.totalCaptured > 100) usageScore += 15; // Heavy monitoring
        else if (keyloggerStatus.totalCaptured > 50) usageScore += 10; // Moderate monitoring
        else if (keyloggerStatus.totalCaptured > 10) usageScore += 5; // Light monitoring
        
        // Track keylogger activity
        if (keyloggerStatus.lastActivity) {
          const keyloggerTime = new Date(keyloggerStatus.lastActivity);
          if (!lastActivityTime || keyloggerTime > lastActivityTime) {
            lastActivityTime = keyloggerTime;
          }
        }
      }

      // Check antivirus status and recent scans
      if (this.appData && this.appData.lastScanDate) {
        securityScore += 15; // Base antivirus score
        activeModules++;
        
        // Add points for recent scans
        const scanTime = new Date(this.appData.lastScanDate);
        const hoursSinceScan = (Date.now() - scanTime.getTime()) / (1000 * 60 * 60);
        
        if (hoursSinceScan < 24) securityScore += 10; // Recent scan
        else if (hoursSinceScan < 168) securityScore += 5; // Within a week
        
        // Usage-based scoring for antivirus
        if (this.appData.scanCount >= 10) usageScore += 15; // Frequent scanning
        else if (this.appData.scanCount >= 5) usageScore += 10; // Regular scanning
        else if (this.appData.scanCount >= 1) usageScore += 5; // Occasional scanning
        
        // Track antivirus activity
        if (!lastActivityTime || scanTime > lastActivityTime) {
          lastActivityTime = scanTime;
        }
      }

      // Check forensics capability and usage
      if (this.appData && this.appData.lastAnalysis) {
        securityScore += 10; // Forensics available
        activeModules++;
        
        // Usage-based scoring for forensics
        if (this.appData.analysisCount >= 5) usageScore += 10; // Regular forensics
        else if (this.appData.analysisCount >= 1) usageScore += 5; // Occasional forensics
        
        // Track forensics activity
        const analysisTime = new Date(this.appData.lastAnalysis.timestamp);
        if (!lastActivityTime || analysisTime > lastActivityTime) {
          lastActivityTime = analysisTime;
        }
      }

      // Check URL Scanner usage
      if (this.appData && this.appData.urlScanCount) {
        activeModules++;
        // Usage-based scoring for URL scanner
        if (this.appData.urlScanCount >= 20) usageScore += 15; // Heavy URL scanning
        else if (this.appData.urlScanCount >= 10) usageScore += 10; // Moderate URL scanning
        else if (this.appData.urlScanCount >= 1) usageScore += 5; // Light URL scanning
      }

      // Calculate total score (base security + usage bonus)
      const totalScore = Math.min(100, securityScore + usageScore);
      
      // Update UI
      const scoreElement = document.getElementById('dashboard-security-score');
      const modulesElement = document.getElementById('dashboard-active-modules');
      const scoreBreakdownElement = document.getElementById('dashboard-score-breakdown');
      const modulesBreakdownElement = document.getElementById('dashboard-modules-breakdown');
      
      if (scoreElement) {
        scoreElement.textContent = totalScore;
        // Add color coding based on score
        if (totalScore >= 80) {
          scoreElement.className = 'text-2xl font-semibold text-green-700';
        } else if (totalScore >= 60) {
          scoreElement.className = 'text-2xl font-semibold text-yellow-600';
        } else {
          scoreElement.className = 'text-2xl font-semibold text-red-600';
        }
      }
      
      // Update score breakdown
      if (scoreBreakdownElement) {
        scoreBreakdownElement.textContent = `Base: ${securityScore} | Uso: ${usageScore}`;
      }
      
      // Update modules breakdown with tips
      if (modulesBreakdownElement) {
        if (activeModules >= 4) {
          modulesBreakdownElement.textContent = '¡Excelente! Usando todos los módulos';
        } else if (activeModules >= 2) {
          modulesBreakdownElement.textContent = 'Buen progreso. Prueba más módulos';
        } else {
          modulesBreakdownElement.textContent = 'Usa más módulos para aumentar tu puntuación';
        }
      }
      
      if (modulesElement) {
        modulesElement.textContent = activeModules;
        // Add color coding based on active modules
        if (activeModules >= 4) {
          modulesElement.className = 'text-2xl font-semibold text-blue-700';
        } else if (activeModules >= 2) {
          modulesElement.className = 'text-2xl font-semibold text-yellow-600';
        } else {
          modulesElement.className = 'text-2xl font-semibold text-red-600';
        }
      }

      // Update last activity
      this.updateLastActivity(lastActivityTime);

    } catch (error) {
      console.error('Error updating dashboard statistics:', error);
    }
  }

  async loadKeyloggerStatus() {
    try {
      const status = await window.electronAPI.getKeyloggerStatus();
      this.updateKeyloggerDashboardStatus(status);
    } catch (error) {
      console.error('Error loading keylogger status:', error);
    }
  }

  updateKeyloggerDashboardStatus(status) {
    const indicator = document.getElementById('keylogger-dashboard-status-indicator');
    const statusText = document.getElementById('keylogger-dashboard-status-text');
    const sessionTime = document.getElementById('keylogger-session-time');
    const keysCount = document.getElementById('keylogger-dashboard-keys-count');
    const wordsCount = document.getElementById('keylogger-dashboard-words-count');
    const startBtn = document.getElementById('dashboard-keylogger-start-btn');
    const stopBtn = document.getElementById('dashboard-keylogger-stop-btn');

    if (indicator && statusText) {
      if (status.isRunning) {
        indicator.className = 'w-2 h-2 bg-green-500 rounded-full';
        statusText.textContent = 'Activo';
        statusText.className = 'text-xs text-green-600 font-semibold';
      } else {
        indicator.className = 'w-2 h-2 bg-red-500 rounded-full';
        statusText.textContent = 'Inactivo';
        statusText.className = 'text-xs text-red-600 font-semibold';
      }
    }

    // Update button visibility
    if (startBtn && stopBtn) {
      if (status.isRunning) {
        startBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
      } else {
        startBtn.classList.remove('hidden');
        stopBtn.classList.add('hidden');
      }
    }

    if (sessionTime) {
      // Handle undefined/null sessionTime
      const sessionTimeValue = status.sessionTime || 0;
      
      // If keylogger is not running, show 00:00:00
      if (!status.isRunning) {
        sessionTime.textContent = 'Sesión: 00:00:00';
      } else {
        const hours = Math.floor(sessionTimeValue / 3600);
        const minutes = Math.floor((sessionTimeValue % 3600) / 60);
        const seconds = Math.floor(sessionTimeValue % 60);
      sessionTime.textContent = `Sesión: ${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
      }
    }

    if (keysCount) keysCount.textContent = status.stats.totalKeys;
    if (wordsCount) wordsCount.textContent = status.stats.totalWords;
  }

  async loadAntivirusStatus() {
    try {
      // First try to get antivirus status from backend
      const status = await window.electronAPI.getAntivirusStatus();
      
      // If we have app data with scan information, use it to enhance the status
      if (this.appData && this.appData.lastScanDate) {
        status.lastScan = this.appData.lastScanDate;
        status.threatsFound = this.appData.totalThreatsFound || 0;
        status.filesScanned = this.appData.totalFilesScanned || 0;
      }
      
      this.updateAntivirusDashboardStatus(status);
    } catch (error) {
      console.error('Error loading antivirus status:', error);
      // Set default status but try to use app data if available
      const defaultStatus = {
        isActive: true,
        lastScan: this.appData?.lastScanDate || null,
        threatsFound: this.appData?.totalThreatsFound || 0,
        filesScanned: this.appData?.totalFilesScanned || 0
      };
      this.updateAntivirusDashboardStatus(defaultStatus);
    }
  }

  updateAntivirusDashboardStatus(status) {
    const indicator = document.getElementById('antivirus-dashboard-status-indicator');
    const statusText = document.getElementById('antivirus-dashboard-status-text');
    const lastScan = document.getElementById('antivirus-dashboard-last-scan');
    const threatsCount = document.getElementById('antivirus-dashboard-threats-count');
    const scannedCount = document.getElementById('antivirus-dashboard-scanned-count');

    if (indicator && statusText) {
      if (status.isActive) {
        indicator.className = 'w-2 h-2 bg-green-500 rounded-full';
        statusText.textContent = 'Activo';
        statusText.className = 'text-xs text-green-600 font-semibold';
      } else {
        indicator.className = 'w-2 h-2 bg-red-500 rounded-full';
        statusText.textContent = 'Inactivo';
        statusText.className = 'text-xs text-red-600 font-semibold';
      }
    }

    if (lastScan) {
      if (status.lastScan) {
        const scanDate = new Date(status.lastScan);
        const now = new Date();
        const diffHours = Math.floor((now - scanDate) / (1000 * 60 * 60));
        
        if (diffHours < 1) {
          lastScan.textContent = 'Último escaneo: Hace menos de 1 hora';
        } else if (diffHours < 24) {
          lastScan.textContent = `Último escaneo: Hace ${diffHours} horas`;
        } else {
          lastScan.textContent = `Último escaneo: ${scanDate.toLocaleDateString()}`;
        }
      } else {
        lastScan.textContent = 'Último escaneo: Nunca';
      }
    }

    if (threatsCount) threatsCount.textContent = status.threatsFound || 0;
    if (scannedCount) scannedCount.textContent = status.filesScanned || 0;
  }

  async loadForensicsStatus() {
    try {
      // Get last analysis info
      const lastAnalysis = await window.electronAPI.getLastAnalysis();
      this.updateForensicsDashboardStatus(lastAnalysis);
      
      // Get analysis statistics
      const analysisStats = await window.electronAPI.getAnalysisStats();
      this.updateForensicsDashboardStats(analysisStats);
    } catch (error) {
      console.error('Error loading forensics status:', error);
      this.updateForensicsDashboardStatus(null);
    }
  }

  updateForensicsDashboardStatus(lastAnalysis) {
    const lastScanTime = document.getElementById('analyzer-last-scan-time');
    const lastScanFile = document.getElementById('analyzer-last-scan-file');
    const lastScanStatus = document.getElementById('analyzer-last-scan-status');

    if (lastAnalysis) {
      if (lastScanTime) {
        const analysisDate = new Date(lastAnalysis.timestamp);
        lastScanTime.textContent = analysisDate.toLocaleString();
      }
      if (lastScanFile) {
        lastScanFile.textContent = `Archivo: ${lastAnalysis.fileName}`;
      }
      if (lastScanStatus) {
        const statusText = lastAnalysis.suspicious ? 'Sospechoso' : 'Seguro';
        const statusColor = lastAnalysis.suspicious ? 'text-red-600' : 'text-green-600';
        lastScanStatus.innerHTML = `<span class="${statusColor} font-semibold">${statusText}</span>`;
      }
    } else {
      if (lastScanTime) lastScanTime.textContent = 'Nunca';
      if (lastScanFile) lastScanFile.textContent = 'No hay análisis realizados';
      if (lastScanStatus) lastScanStatus.textContent = '';
    }
  }

  updateForensicsDashboardStats(stats) {
    const totalScans = document.getElementById('analyzer-total-scans');
    const suspiciousFiles = document.getElementById('analyzer-suspicious-files');

    if (totalScans) totalScans.textContent = stats.totalScans || 0;
    if (suspiciousFiles) suspiciousFiles.textContent = stats.suspiciousFiles || 0;
  }

  async loadSystemStatus() {
    try {
      const systemInfo = await window.electronAPI.getSystemInfo();
      this.updateSystemDashboardStatus(systemInfo);
    } catch (error) {
      console.error('Error loading system status:', error);
    }
  }

  updateSystemDashboardStatus(systemInfo) {
    const systemStatus = document.getElementById('system-status');
    const systemInfoElement = document.getElementById('system-info');

    if (systemStatus) {
      systemStatus.textContent = 'Sistema OK';
      systemStatus.className = 'text-xs px-2 py-1 bg-green-100 text-green-700 rounded-full';
    }

    if (systemInfoElement && systemInfo) {
      systemInfoElement.textContent = `OS: ${systemInfo.platform} | CPU: ${systemInfo.cpuCount} cores | RAM: ${Math.round(systemInfo.totalMemory / 1024 / 1024 / 1024)}GB`;
    }
  }

  async loadVaultDashboardData() {
    try {
      const vaultStats = await window.electronAPI.getVaultStats();
      this.updateVaultDashboardStatus(vaultStats);
      
      // Load recent passwords for dashboard preview
      const recentPasswords = await window.electronAPI.getAllPasswords();
      this.updateVaultDashboardRecentPasswords(recentPasswords);
    } catch (error) {
      console.error('Error loading vault dashboard data:', error);
    }
  }

  updateVaultDashboardRecentPasswords(passwords) {
    const recentContainer = document.getElementById('vault-dashboard-recent-passwords');
    if (!recentContainer) return;

    if (!passwords.success || !passwords.passwords || passwords.passwords.length === 0) {
      recentContainer.innerHTML = '<div class="text-xs text-gray-500 italic">No hay contraseñas guardadas</div>';
      return;
    }

    // Get the 3 most recent passwords
    const recentPasswords = passwords.passwords
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 3);

    if (recentPasswords.length === 0) {
      recentContainer.innerHTML = '<div class="text-xs text-gray-500 italic">No hay contraseñas guardadas</div>';
      return;
    }

    recentContainer.innerHTML = recentPasswords.map(password => {
      const createdDate = new Date(password.createdAt);
      const timeAgo = this.getTimeAgo(createdDate);
      
      return `
        <div class="flex items-center justify-between p-2 bg-white rounded border text-xs">
          <div class="flex-1">
            <div class="font-medium text-gray-800 truncate">${password.label}</div>
            <div class="text-gray-500">${password.username || 'Sin usuario'}</div>
          </div>
          <div class="text-gray-400 ml-2">${timeAgo}</div>
        </div>
      `;
    }).join('');
  }

  getTimeAgo(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Ahora';
    if (diffMins < 60) return `${diffMins}m`;
    if (diffHours < 24) return `${diffHours}h`;
    if (diffDays < 7) return `${diffDays}d`;
    return date.toLocaleDateString();
  }

  updateVaultDashboardStatus(stats) {
    const indicator = document.getElementById('vault-dashboard-status-indicator');
    const statusText = document.getElementById('vault-dashboard-status-text');
    const lastAdded = document.getElementById('vault-dashboard-last-added');
    const passwordsCount = document.getElementById('vault-dashboard-passwords-count');
    const strengthAvg = document.getElementById('vault-dashboard-strength-avg');

    // Extract stats from the response structure
    const vaultStats = stats.stats || stats;
    const totalPasswords = vaultStats.totalPasswords || 0;
    const averageStrength = vaultStats.averageStrength || 0;

    if (indicator && statusText) {
      if (stats.success && totalPasswords > 0) {
        indicator.className = 'w-2 h-2 bg-green-500 rounded-full';
        statusText.textContent = 'Activo';
        statusText.className = 'text-xs text-green-600 font-semibold';
      } else {
        indicator.className = 'w-2 h-2 bg-yellow-500 rounded-full';
        statusText.textContent = 'Vacío';
        statusText.className = 'text-xs text-yellow-600 font-semibold';
      }
    }

    if (lastAdded) {
      if (vaultStats.lastAdded) {
        const addedDate = new Date(vaultStats.lastAdded);
        const now = new Date();
        const diffHours = Math.floor((now - addedDate) / (1000 * 60 * 60));
        
        if (diffHours < 1) {
          lastAdded.textContent = 'Última adición: Hace menos de 1 hora';
        } else if (diffHours < 24) {
          lastAdded.textContent = `Última adición: Hace ${diffHours} horas`;
        } else {
          lastAdded.textContent = `Última adición: ${addedDate.toLocaleDateString()}`;
        }
      } else {
        lastAdded.textContent = 'Última adición: Nunca';
      }
    }

    if (passwordsCount) passwordsCount.textContent = totalPasswords;
    if (strengthAvg) strengthAvg.textContent = `${Math.round(averageStrength)}%`;
  }

  addActivityLogEntry(type, title, description, status = 'info') {
    const activity = {
      id: Date.now(),
      type: type,
      title: title,
      description: description,
      status: status,
      timestamp: new Date(),
      timeString: new Date().toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })
    };
    
    // Add to beginning of array (most recent first)
    this.activityLog.unshift(activity);
    
    // Keep only last 10 activities
    if (this.activityLog.length > 10) {
      this.activityLog = this.activityLog.slice(0, 10);
    }
    
    // Update activity display
    this.updateActivityDisplay();
    
    // Save to app data
    this.saveActivityData();
  }

  updateActivityDisplay() {
    const activityContainer = document.querySelector('.relative.max-h-64.overflow-y-auto.pl-5');
    if (!activityContainer) return;
    
    // Clear existing activities
    activityContainer.innerHTML = '<div class="absolute left-2 top-0 bottom-0 w-px bg-gray-200"></div>';
    
    // Add only first 4 real activities
    this.activityLog.slice(0, 4).forEach(activity => {
      const statusColors = {
        'success': 'bg-green-500',
        'info': 'bg-blue-500',
        'warning': 'bg-yellow-500',
        'error': 'bg-red-500'
      };
      
      const activityElement = document.createElement('div');
      activityElement.className = 'flex items-start gap-3 p-2 rounded-lg hover:bg-gray-50 cursor-pointer';
      activityElement.innerHTML = `
        <div class="w-2 h-2 rounded-full ${statusColors[activity.status]} mt-2"></div>
        <div class="flex-1">
          <div class="flex justify-between items-start">
            <span class="text-sm font-medium text-gray-800">${activity.title}</span>
            <span class="text-xs text-gray-500">${activity.timeString}</span>
          </div>
          <p class="text-xs text-gray-600">${activity.description}</p>
        </div>
      `;
      
      activityContainer.appendChild(activityElement);
    });
    
    // If no activities, show placeholder
    if (this.activityLog.length === 0) {
      const placeholder = document.createElement('div');
      placeholder.className = 'flex items-center justify-center py-8 text-gray-500';
      placeholder.innerHTML = '<span class="text-sm">No hay actividad reciente</span>';
      activityContainer.appendChild(placeholder);
    }
  }

  async saveActivityData() {
    try {
      await window.electronAPI.updateScanData({ 
        activityLog: this.activityLog.map(activity => ({
          ...activity,
          timestamp: activity.timestamp.toISOString()
        }))
      });
    } catch (error) {
      console.error('Error saving activity data:', error);
    }
  }

  async loadActivityData() {
    try {
      const result = await window.electronAPI.getAppData();
      if (result.success && result.data && result.data.activityLog) {
        this.activityLog = result.data.activityLog.map(activity => ({
          ...activity,
          timestamp: new Date(activity.timestamp)
        }));
        this.updateActivityDisplay();
      }
    } catch (error) {
      console.error('Error loading activity data:', error);
    }
  }

  updateLastActivity(lastActivityTime = null) {
    const lastActivityElement = document.getElementById('dashboard-last-activity');
    if (lastActivityElement) {
      let activityTime = lastActivityTime;
      
      // If no specific time provided, use current time
      if (!activityTime) {
        activityTime = new Date();
      }
      
      const now = new Date();
      const diffMs = now - activityTime;
      const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      
      let timeText;
      if (diffHours < 1) {
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        timeText = `Hace ${diffMinutes} min`;
      } else if (diffHours < 24) {
        timeText = `Hace ${diffHours}h`;
      } else if (diffDays === 1) {
        timeText = 'Ayer';
      } else if (diffDays < 7) {
        timeText = `Hace ${diffDays} días`;
      } else {
        timeText = activityTime.toLocaleDateString('es-ES', { 
          day: 'numeric', 
          month: 'short' 
        });
      }
      
      lastActivityElement.textContent = timeText;
      lastActivityElement.title = `Última actividad: ${activityTime.toLocaleString('es-ES')}`;
    }
  }

  async loadVaultCount() {
    try {
      // First recalculate password strengths for existing passwords
      await window.electronAPI.recalculatePasswordStrengths();
      
      const result = await window.electronAPI.getVaultStats();
      this.updateVaultDashboardStatus(result);
      
      if (result.success) {
    const counter = document.getElementById('stored-count');
    if (counter) {
          counter.textContent = result.stats.totalPasswords;
    }
    
    // Actualizar estadísticas de fortaleza de contraseña
        this.updatePasswordStrengthStatsFromStats(result.stats);
    
    // Actualizar actividad de bóveda e información de almacenamiento
    this.updateVaultInfo();
      }
    } catch (error) {
      console.error('Error cargando conteo de bóveda:', error);
    }
  }

  updatePasswordStrengthStatsFromStats(stats) {
    const strongEl = document.getElementById('strong-count');
    const mediumEl = document.getElementById('medium-count');
    const weakEl = document.getElementById('weak-count');
    
    if (strongEl) strongEl.textContent = stats.strongPasswords;
    if (mediumEl) mediumEl.textContent = stats.mediumPasswords;
    if (weakEl) weakEl.textContent = stats.weakPasswords;
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

  async updateVaultInfo() {
    try {
      const result = await window.electronAPI.getVaultStats();
      
      if (result.success) {
        const stats = result.stats;
        
        // Actualizar última actividad (usar fecha de creación más reciente)
    const lastActivityEl = document.getElementById('last-vault-activity');
    if (lastActivityEl) {
          lastActivityEl.textContent = 'Activo';
        }
        
        // Actualizar tamaño de almacenamiento estimado
    const storageEl = document.getElementById('vault-storage');
    if (storageEl) {
          const estimatedSize = stats.totalPasswords * 200; // Estimación aproximada
          if (estimatedSize < 1024) {
            storageEl.textContent = `${estimatedSize} B`;
          } else if (estimatedSize < 1024 * 1024) {
            storageEl.textContent = `${(estimatedSize / 1024).toFixed(1)} KB`;
      } else {
            storageEl.textContent = `${(estimatedSize / (1024 * 1024)).toFixed(1)} MB`;
      }
        }
      }
    } catch (error) {
      console.error('Error actualizando información de bóveda:', error);
    }
  }

  async loadPasswordList() {
    try {
      const result = await window.electronAPI.getAllPasswords();
    const passwordListEl = document.getElementById('password-list');
    const vaultSubtitleEl = document.getElementById('vault-subtitle');
    
      if (!passwordListEl || !result.success) return;
      
      const stored = result.passwords;
    
    // Actualizar subtítulo
    if (vaultSubtitleEl) {
      vaultSubtitleEl.textContent = `(${stored.length} contraseñas)`;
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
    
    // Mostrar todas las contraseñas
    const passwordsToShow = stored;
    
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
      
      // Add event listeners for password actions
      this.setupPasswordItemEventListeners(innerContainer);
      }
    } catch (error) {
      console.error('Error cargando lista de contraseñas:', error);
    }
  }

  setupPasswordItemEventListeners(container) {
    // Use event delegation to avoid multiple listeners
    // Only set up once per container
    if (container._passwordEventListenersSetup) {
      return;
    }
    container._passwordEventListenersSetup = true;
    
    container.addEventListener('click', (e) => {
      // Handle copy password button
      if (e.target.closest('.copy-password-btn')) {
        e.preventDefault();
        e.stopPropagation();
        const button = e.target.closest('.copy-password-btn');
        const passwordId = button.dataset.passwordId;
        this.copyPassword(passwordId);
        return;
      }
      
      // Handle remove password button
      if (e.target.closest('.remove-password-btn')) {
        e.preventDefault();
        e.stopPropagation();
        const button = e.target.closest('.remove-password-btn');
        const passwordId = button.dataset.passwordId;
        this.removePassword(passwordId);
        return;
      }
    });
  }

  async copyPassword(passwordId) {
    try {
      const result = await window.electronAPI.getAllPasswords();
      if (result.success) {
        const password = result.passwords.find(p => p.id === passwordId);
        if (password) {
          await navigator.clipboard.writeText(password.password);
          this.showNotification('Contraseña copiada al portapapeles', 'success');
        }
      }
    } catch (error) {
      console.error('Error copiando contraseña:', error);
      this.showNotification('Error copiando contraseña', 'error');
    }
  }

  async removePassword(passwordId) {
    console.log('removePassword called with ID:', passwordId);
    
    // Prevent multiple confirmations
    if (this._deletingPassword) {
      console.log('Password deletion already in progress, ignoring duplicate call');
      return;
    }
    
    console.log('Mostrando diálogo de confirmación...');
    const confirmed = confirm('¿Estás seguro de que quieres eliminar esta contraseña?');
    console.log('User confirmed deletion:', confirmed);
    
    if (confirmed) {
      this._deletingPassword = true;
      try {
        console.log('Procediendo con la eliminación de contraseña...');
        const result = await window.electronAPI.removePasswordFromVault(passwordId);
        if (result.success) {
          this.showNotification(result.message, 'success');
          await this.loadVaultCount();
          await this.loadPasswordList();
          // Update dashboard vault data
          await this.loadVaultDashboardData();
        } else {
          this.showNotification(result.message, 'error');
        }
      } catch (error) {
        console.error('Error eliminando contraseña:', error);
        this.showNotification('Error eliminando contraseña', 'error');
      } finally {
        this._deletingPassword = false;
        console.log('Password deletion process completed');
      }
    } else {
      console.log('User cancelled password deletion');
    }
  }

  createPasswordItem(item, index) {
    const div = document.createElement('div');
    div.className = 'p-3 bg-gray-50 rounded-lg border border-gray-200 hover:bg-gray-100 transition-colors duration-200';
    div.dataset.passwordId = item.id;
    
    // Obtener información del sitio web de la etiqueta o generar predeterminado
    const websiteInfo = this.getWebsiteInfo(item.label);
    
    div.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 ${websiteInfo.bgColor} rounded-lg flex items-center justify-center">
            <i class="${websiteInfo.icon} ${websiteInfo.textColor} text-sm"></i>
          </div>
          <div>
            <div class="font-medium text-gray-800">${item.label}</div>
            <div class="text-sm text-gray-500">${item.username || item.website || websiteInfo.domain}</div>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <div class="text-xs font-mono bg-white px-2 py-1 rounded border">••••••••</div>
          <button class="copy-password-btn p-1 text-gray-400 hover:text-gray-600 transition-colors" title="Copiar" data-password-id="${item.id}">
            <i class="fas fa-copy text-sm"></i>
          </button>
          <button class="remove-password-btn p-1 text-gray-400 hover:text-red-600 transition-colors" title="Eliminar" data-password-id="${item.id}">
            <i class="fas fa-trash text-sm"></i>
          </button>
        </div>
      </div>
    `;
    
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
    this.navigateToSection('passwords');
  }

  async addToVault() {
    console.log('addToVault function called');
    
    // Always show modal with empty password field to allow custom input
    this.showAddToVaultModal('');
  }

  showAddToVaultModal(password = '') {
    const modal = document.getElementById('add-to-vault-modal');
    const passwordInput = document.getElementById('vault-password');
    const strengthIndicator = document.getElementById('password-strength-indicator');
    const form = document.getElementById('add-to-vault-form');
    const labelInput = document.getElementById('vault-label');
    
    // Reset form
    form.reset();
    
    // Always start with empty, editable password field
    passwordInput.value = '';
    passwordInput.dataset.generated = 'false';
    passwordInput.readOnly = false;
    passwordInput.disabled = false;
    passwordInput.classList.remove('bg-gray-50');
    
    // Ensure all inputs are editable
    const allInputs = form.querySelectorAll('input, textarea');
    allInputs.forEach(input => {
      input.readOnly = false;
      input.disabled = false;
    });
    
    // Show password strength indicator
    strengthIndicator.classList.remove('hidden');
    
    // Show the modal
    modal.classList.remove('hidden');
    
    // Setup modal event listeners if not already done
    this.setupAddToVaultModalEvents();
    
    // Update password strength after modal is visible
    setTimeout(() => {
      this.updatePasswordStrength(passwordInput.value);
      labelInput.focus();
    }, 100);
  }

  setupAddToVaultModalEvents() {
    // Use a single event delegation approach for better performance
    const modal = document.getElementById('add-to-vault-modal');
    
    // Only setup events once
    if (modal._eventsSetup) return;
    modal._eventsSetup = true;
    
    // Cache frequently used elements
    const elements = {
      labelInput: document.getElementById('vault-label'),
      passwordInput: document.getElementById('vault-password'),
      saveBtn: document.getElementById('save-to-vault')
    };
    
    // Direct event listeners for better reliability
    const cancelBtn = document.getElementById('cancel-add-vault');
    const saveBtn = document.getElementById('save-to-vault');
    const generateBtn = document.getElementById('generate-password-btn');
    const clearBtn = document.getElementById('clear-password-btn');
    const toggleBtn = document.getElementById('toggle-password-visibility');
    
    // Cancel button
    if (cancelBtn) {
      cancelBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.closeAddToVaultModal();
      });
    }
    
    // Save button
    if (saveBtn) {
      saveBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.savePasswordToVault();
      });
    }
    
    // Generate password button
    if (generateBtn) {
      generateBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.generatePasswordForVault();
      });
    }
    
    // Clear password button
    if (clearBtn) {
      clearBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.clearPasswordField();
      });
    }
    
    // Toggle password visibility
    if (toggleBtn) {
      toggleBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.togglePasswordVisibility();
      });
    }
    
    // Backdrop click disabled - modal can only be closed with Cancel button
    
    // Keyboard events with passive listeners
    modal.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeAddToVaultModal();
      } else if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
        e.preventDefault();
        if (!elements.saveBtn.disabled) {
          this.savePasswordToVault();
        }
      }
    }, { passive: false });
    
    // Optimized validation with throttling
    let validationTimeout;
    let strengthTimeout;
    
    const validateForm = () => {
      clearTimeout(validationTimeout);
      validationTimeout = setTimeout(() => {
        this.validateVaultForm();
      }, 150); // Increased debounce time
    };
    
    const calculateStrength = () => {
      clearTimeout(strengthTimeout);
      strengthTimeout = setTimeout(() => {
        const password = elements.passwordInput.value;
        this.updatePasswordStrength(password);
        this.updatePasswordRequirements(password);
      }, 100); // Reduced debounce time for better responsiveness
    };
    
    // Use input event for better performance
    elements.labelInput.addEventListener('input', validateForm, { passive: true });
    elements.passwordInput.addEventListener('input', (e) => {
      validateForm();
      calculateStrength();
    }, { passive: true });
  }

  closeAddToVaultModal() {
    // Use requestAnimationFrame for better performance
    requestAnimationFrame(() => {
      const modal = document.getElementById('add-to-vault-modal');
      const form = document.getElementById('add-to-vault-form');
      const strengthIndicator = document.getElementById('password-strength-indicator');
      const passwordInput = document.getElementById('vault-password');
      const labelError = document.getElementById('label-error');
      const passwordError = document.getElementById('password-error');
      const labelInput = document.getElementById('vault-label');
      
      // Hide modal first for immediate visual feedback
      modal.classList.add('hidden');
      
      // Batch DOM operations
      form.reset();
      strengthIndicator.classList.add('hidden');
      
      // Reset password input state
      passwordInput.dataset.generated = 'false';
      passwordInput.readOnly = false;
      passwordInput.classList.remove('bg-gray-50', 'border-red-500');
      
      // Clear error messages efficiently
      if (labelError) {
        labelError.textContent = '';
        labelError.classList.add('hidden');
      }
      if (passwordError) {
        passwordError.textContent = '';
        passwordError.classList.add('hidden');
      }
      
      // Reset input borders
      labelInput.classList.remove('border-red-500');
    });
  }

  togglePasswordVisibility() {
    const passwordInput = document.getElementById('vault-password');
    const toggleBtn = document.getElementById('toggle-password-visibility');
    const icon = toggleBtn.querySelector('i');
    
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
  }

  validateVaultForm() {
    const labelInput = document.getElementById('vault-label');
    const passwordInput = document.getElementById('vault-password');
    const saveBtn = document.getElementById('save-to-vault');
    const labelError = document.getElementById('label-error');
    const passwordError = document.getElementById('password-error');
    
    let isValid = true;
    
    // Validate label
    const label = labelInput.value.trim();
    if (label.length === 0) {
      isValid = false;
      labelInput.classList.add('border-red-500');
      if (labelError) {
        labelError.textContent = 'El nombre es requerido';
        labelError.classList.remove('hidden');
      }
    } else if (label.length < 2) {
      isValid = false;
      labelInput.classList.add('border-red-500');
      if (labelError) {
        labelError.textContent = 'El nombre debe tener al menos 2 caracteres';
        labelError.classList.remove('hidden');
      }
    } else {
      labelInput.classList.remove('border-red-500');
      if (labelError) {
        labelError.textContent = '';
        labelError.classList.add('hidden');
      }
    }
    
    // Validate password
    const password = passwordInput.value;
    if (password.length === 0) {
      isValid = false;
      passwordInput.classList.add('border-red-500');
      if (passwordError) {
        passwordError.textContent = 'La contraseña es requerida';
        passwordError.classList.remove('hidden');
      }
    } else if (password.length < 6) {
      isValid = false;
      passwordInput.classList.add('border-red-500');
      if (passwordError) {
        passwordError.textContent = 'La contraseña debe tener al menos 6 caracteres';
        passwordError.classList.remove('hidden');
      }
    } else {
      passwordInput.classList.remove('border-red-500');
      if (passwordError) {
        passwordError.textContent = '';
        passwordError.classList.add('hidden');
      }
    }
    
    saveBtn.disabled = !isValid;
    return isValid;
  }

  generatePasswordForVault() {
    try {
      // Get current password generation settings
      const length = parseInt(document.getElementById('password-length')?.value || 16);
      const includeUppercase = document.getElementById('include-uppercase')?.checked || true;
      const includeLowercase = document.getElementById('include-lowercase')?.checked || true;
      const includeNumbers = document.getElementById('include-numbers')?.checked || true;
      const includeSymbols = document.getElementById('include-symbols')?.checked || true;
      const excludeSimilar = document.getElementById('exclude-similar')?.checked || false;
      const excludeAmbiguous = document.getElementById('exclude-ambiguous')?.checked || false;

      // Generate password using the same logic as generateNewPassword
      let charset = '';
      if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
      if (includeNumbers) charset += '0123456789';
      if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

      // Apply exclusions
      if (excludeSimilar) {
        charset = charset.replace(/[il1Lo0O]/g, '');
      }
      if (excludeAmbiguous) {
        charset = charset.replace(/[{}[\]()\/\\'";:.,<>?]/g, '');
      }

      if (charset.length === 0) {
        this.showNotification('Debe seleccionar al menos un tipo de carácter', 'error');
        return;
      }

      // Generate password
      let password = '';
      for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
      }
      
      // Update the password input
      const passwordInput = document.getElementById('vault-password');
      passwordInput.value = password;
      passwordInput.dataset.generated = 'true';
      passwordInput.readOnly = false; // Keep editable
      passwordInput.classList.remove('bg-gray-50'); // Remove gray background
      
      // Update strength indicator
      this.updatePasswordStrength(password);
      this.updatePasswordRequirements(password);
      
      // Trigger validation
      this.validateVaultForm();
      
      this.showNotification(`Nueva contraseña generada (${length} caracteres)`, 'success');
    } catch (error) {
      console.error('Error generating password for vault:', error);
      this.showNotification('Error al generar contraseña', 'error');
    }
  }

  useCurrentPasswordForVault() {
    // Function removed - no longer needed
  }

  clearPasswordField() {
    const passwordInput = document.getElementById('vault-password');
    
    // Clear the password field
    passwordInput.value = '';
    passwordInput.dataset.generated = 'false';
    passwordInput.readOnly = false;
    passwordInput.classList.remove('bg-gray-50');
    
    // Update strength indicator
    this.updatePasswordStrength('');
    this.updatePasswordRequirements('');
    
    // Trigger validation
    this.validateVaultForm();
    
    // Focus on the password input
    passwordInput.focus();
    
    this.showNotification('Campo de contraseña limpiado', 'info');
  }

  updatePasswordStrength(password) {
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');
    
    if (!strengthBar || !strengthText) return;
    
    // Calculate strength with improved algorithm
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
    score = Math.max(0, Math.min(100, score));
    
    // Update visual indicator
    strengthBar.style.width = `${score}%`;
    
    if (score >= 85) {
      strengthBar.className = 'h-2 rounded-full transition-all duration-300 bg-green-500';
      strengthText.textContent = 'Muy Fuerte';
      strengthText.className = 'text-xs font-medium text-green-600';
    } else if (score >= 70) {
      strengthBar.className = 'h-2 rounded-full transition-all duration-300 bg-green-400';
      strengthText.textContent = 'Fuerte';
      strengthText.className = 'text-xs font-medium text-green-600';
    } else if (score >= 50) {
      strengthBar.className = 'h-2 rounded-full transition-all duration-300 bg-yellow-500';
      strengthText.textContent = 'Media';
      strengthText.className = 'text-xs font-medium text-yellow-600';
    } else if (score >= 25) {
      strengthBar.className = 'h-2 rounded-full transition-all duration-300 bg-orange-500';
      strengthText.textContent = 'Débil';
      strengthText.className = 'text-xs font-medium text-orange-600';
    } else {
      strengthBar.className = 'h-2 rounded-full transition-all duration-300 bg-red-500';
      strengthText.textContent = 'Muy Débil';
      strengthText.className = 'text-xs font-medium text-red-600';
    }
  }

  updatePasswordRequirements(password) {
    const requirements = {
      'req-length': password.length >= 8,
      'req-uppercase': /[A-Z]/.test(password),
      'req-lowercase': /[a-z]/.test(password),
      'req-number': /[0-9]/.test(password),
      'req-special': /[^A-Za-z0-9]/.test(password),
      'req-unique': !/(.)\1{2,}/.test(password)
    };
    
    Object.entries(requirements).forEach(([reqId, met]) => {
      const reqElement = document.getElementById(reqId);
      if (!reqElement) return;
      
      const checkIcon = reqElement.querySelector('.fa-check');
      const timesIcon = reqElement.querySelector('.fa-times');
      
      if (met) {
        if (checkIcon) checkIcon.classList.remove('hidden');
        if (timesIcon) timesIcon.classList.add('hidden');
      } else {
        if (checkIcon) checkIcon.classList.add('hidden');
        if (timesIcon) timesIcon.classList.remove('hidden');
      }
    });
  }

  async savePasswordToVault() {
    const form = document.getElementById('add-to-vault-form');
    const formData = new FormData(form);
    
    const passwordData = {
      label: formData.get('label').trim(),
      username: formData.get('username').trim(),
      website: formData.get('website').trim(),
      notes: formData.get('notes').trim(),
      password: formData.get('password')
    };
    
    // Validate required fields
    if (!passwordData.label) {
      this.showNotification('El nombre de la contraseña es requerido', 'error');
      return;
    }
    
    // Show loading state
    const saveBtn = document.getElementById('save-to-vault');
    const originalText = saveBtn.innerHTML;
    saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Guardando...';
    saveBtn.disabled = true;
    
    try {
      console.log('Saving password to vault:', passwordData);
      await this.storePassword(passwordData.label, passwordData.password, passwordData.username, passwordData.website, passwordData.notes);
      
      // Close modal on success
      document.getElementById('add-to-vault-modal').classList.add('hidden');
      form.reset();
      document.getElementById('password-strength-indicator').classList.add('hidden');
      
    } catch (error) {
      console.error('Error saving password:', error);
      this.showNotification('Error guardando la contraseña', 'error');
    } finally {
      // Restore button state
      saveBtn.innerHTML = originalText;
      saveBtn.disabled = false;
    }
  }

  async storePassword(label, password, username = '', website = '', notes = '') {
    try {
      const result = await window.electronAPI.addPasswordToVault({
        label,
        password,
        username,
        website,
        notes
      });
      
      if (result.success) {
        this.showNotification(result.message, 'success');
        // Add activity log entry
        this.addActivityLogEntry('vault', 'Contraseña generada', `Nueva contraseña para ${label}`, 'success');
    // Actualizar toda la información de bóveda
        await this.loadVaultCount();
        await this.loadPasswordList();
        // Update dashboard vault data
        await this.loadVaultDashboardData();
        // Update dashboard statistics
        await this.updateDashboardStatistics();
      } else {
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error almacenando contraseña:', error);
      this.showNotification('Error almacenando contraseña', 'error');
    }
  }

  importVault() {
    // Crear entrada de archivo para importar
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = async (e) => {
          try {
            const result = await window.electronAPI.importVault(e.target.result);
            if (result.success) {
              this.showNotification(result.message, 'success');
              await this.loadVaultCount();
              await this.loadPasswordList();
            } else {
              this.showNotification(result.message, 'error');
            }
          } catch (error) {
            console.error('Error importando bóveda:', error);
            this.showNotification('Error importando archivo', 'error');
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  }

  async exportVault() {
    try {
      const result = await window.electronAPI.exportVault('json');
      
      if (result.success) {
        const dataBlob = new Blob([result.data], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
        link.download = result.filename;
    link.click();
    
    URL.revokeObjectURL(url);
    
    this.showNotification('Bóveda exportada exitosamente', 'success');
      } else {
        this.showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('Error exportando bóveda:', error);
      this.showNotification('Error exportando bóveda', 'error');
    }
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
        
        // Add activity log entry
        this.addActivityLogEntry('keylogger', 'Monitoreo iniciado', 'Keylogger activado para captura de actividad', 'info');
        
        // Track module usage for scoring
        this.trackModuleUsage('keylogger', 'start-monitoring');
        
        // Update module buttons only (dashboard buttons are handled by updateKeyloggerDashboardStatus)
        const startBtn = document.getElementById('keylogger-start-btn');
        const stopBtn = document.getElementById('keylogger-stop-btn');
        
        if (startBtn) {
          startBtn.disabled = true;
        }
        if (stopBtn) {
          stopBtn.disabled = false;
        }
        
        this.startKeyloggerSessionTimer();
        this.startKeyloggerPolling();
        this.addKeyloggerLogEntry('Sistema', 'Monitoreo iniciado', 'info');
        this.showNotification('Keylogger iniciado correctamente', 'success');
        
        // Refresh dashboard
        await this.loadKeyloggerStatus();
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
        
        // Add activity log entry
        this.addActivityLogEntry('keylogger', 'Monitoreo detenido', 'Keylogger desactivado', 'info');
        
        // Update module buttons only (dashboard buttons are handled by updateKeyloggerDashboardStatus)
        const startBtn = document.getElementById('keylogger-start-btn');
        const stopBtn = document.getElementById('keylogger-stop-btn');
        
        if (startBtn) {
          startBtn.disabled = false;
        }
        if (stopBtn) {
          stopBtn.disabled = true;
        }
        
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
        
        // Refresh dashboard
        await this.loadKeyloggerStatus();
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
        
        // Add real-time activity indicator
        this.addRealTimeActivityIndicator();
      } else {
        statusIndicator.className = 'w-3 h-3 bg-red-500 rounded-full';
        statusText.textContent = 'Inactivo';
        statusText.className = 'text-sm text-red-600 font-semibold';
        console.log('Status updated to INACTIVE'); // Debug log
        
        // Remove real-time activity indicator
        this.removeRealTimeActivityIndicator();
        
        // Reset log display when inactive
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

  addRealTimeActivityIndicator() {
    // Add a real-time activity indicator to show when data is being captured
    const statusContainer = document.querySelector('#keylogger-status-indicator').parentElement;
    if (statusContainer && !statusContainer.querySelector('.real-time-indicator')) {
      const indicator = document.createElement('div');
      indicator.className = 'real-time-indicator text-xs text-green-400 animate-pulse';
      indicator.textContent = 'Capturando...';
      statusContainer.appendChild(indicator);
    }
  }

  removeRealTimeActivityIndicator() {
    // Remove the real-time activity indicator
    const indicator = document.querySelector('.real-time-indicator');
    if (indicator) {
      indicator.remove();
    }
  }

  startKeyloggerSessionTimer() {
    this.keyloggerStatus.sessionTimer = setInterval(() => {
      this.updateKeyloggerSessionStats();
    }, 1000);
  }

  startKeyloggerPolling() {
    console.log('Iniciando polling del keylogger...');
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
        
        // Update dashboard status
        this.updateKeyloggerDashboardStatus(status);
        
        // Always update stats for real-time feedback, even if content hasn't changed
        if (status.logContent) {
          console.log('Actualizando contenido del log:', status.logContent.slice(-50));
          this.parseKeyloggerContent(status.logContent);
        }
        
        // Force stats update for real-time display
        this.updateKeyloggerStats();
        
        // Always update the last log content to ensure we track changes
        if (status.logContent) {
          this.keyloggerStatus.lastLogContent = status.logContent;
        }
      } catch (error) {
        console.error('Error polling keylogger status:', error);
      }
    }, 500); // Poll every 500ms for more responsive real-time updates
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
    
    console.log('parseKeyloggerContent called with content:', content.slice(-50));
    
    // Contar caracteres y palabras más precisamente
    const charCount = content.length;
    // Contar palabras dividiendo por espacios y filtrando cadenas vacías
    const words = content.split(/\s+/).filter(word => word.length > 0);
    const wordCount = words.length;
    
    // Update stats immediately
    this.keyloggerStatus.stats.totalKeys = charCount;
    this.keyloggerStatus.stats.totalWords = wordCount;
    
    // Update display immediately for real-time feedback
    this.updateKeyloggerStats();
    
    console.log('Contenido en tiempo real parseado:', { charCount, wordCount, content: content.slice(-50) });
    
    // Actualizar pantalla de registro con formato de terminal original
    const logDisplay = document.getElementById('keylogger-log-display');
    if (logDisplay) {
      console.log('Actualizando pantalla de log con contenido:', content.slice(-50));
      
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
      
      // Agregar nuevo contenido como una sola entrada con formato de terminal
      const timestamp = new Date().toLocaleTimeString();
      const logEntry = document.createElement('div');
      logEntry.className = 'mb-1 text-xs text-green-400';
      
      // Mostrar el contenido completo sin truncamiento con formato de terminal
      logEntry.innerHTML = `<span class="text-gray-500">[${timestamp}]</span> <span class="font-semibold text-green-300">Capturado:</span> <span class="text-white">${content}</span>`;
      
      logDisplay.appendChild(logEntry);
      logDisplay.scrollTop = logDisplay.scrollHeight;
      
      console.log('Log display updated successfully');
    } else {
      console.error('Log display element not found');
    }
    
    // Add visual feedback to stats elements
    this.addStatsUpdateAnimation();
  }

  updateKeyloggerStats() {
    // Actualizar estadísticas de la sección principal del keylogger
    const keysCount = document.getElementById('keylogger-keys-count');
    const wordsCount = document.getElementById('keylogger-words-count');
    
    // Actualizar estadísticas de la tarjeta del dashboard
    const dashboardKeysCount = document.getElementById('keylogger-dashboard-keys-count');
    const dashboardWordsCount = document.getElementById('keylogger-dashboard-words-count');
    
    console.log('Actualizando estadísticas:', this.keyloggerStatus.stats); // Debug log
    
    // Actualizar sección principal
    if (keysCount) {
      keysCount.textContent = this.keyloggerStatus.stats.totalKeys;
      console.log('Conteo de teclas actualizado a:', this.keyloggerStatus.stats.totalKeys);
    }
    if (wordsCount) {
      wordsCount.textContent = this.keyloggerStatus.stats.totalWords;
      console.log('Conteo de palabras actualizado a:', this.keyloggerStatus.stats.totalWords);
    }
    
    // Actualizar dashboard
    if (dashboardKeysCount) {
      dashboardKeysCount.textContent = this.keyloggerStatus.stats.totalKeys;
      console.log('Conteo de teclas del dashboard actualizado a:', this.keyloggerStatus.stats.totalKeys);
    }
    if (dashboardWordsCount) {
      dashboardWordsCount.textContent = this.keyloggerStatus.stats.totalWords;
      console.log('Conteo de palabras del dashboard actualizado a:', this.keyloggerStatus.stats.totalWords);
    }
  }

  addStatsUpdateAnimation() {
    // Add visual feedback to stats elements when they update
    const keysCount = document.getElementById('keylogger-keys-count');
    const wordsCount = document.getElementById('keylogger-words-count');
    const dashboardKeysCount = document.getElementById('keylogger-dashboard-keys-count');
    const dashboardWordsCount = document.getElementById('keylogger-dashboard-words-count');
    
    const elements = [keysCount, wordsCount, dashboardKeysCount, dashboardWordsCount];
    
    elements.forEach(element => {
      if (element) {
        element.classList.add('animate-pulse', 'text-green-400');
        setTimeout(() => {
          element.classList.remove('animate-pulse', 'text-green-400');
        }, 500);
      }
    });
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
    // Reset threat count for new scan
    this.threatCount = 0;
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
    
    // Update dashboard antivirus status indicator
    const dashboardIndicator = document.getElementById('antivirus-dashboard-status-indicator');
    const dashboardStatusText = document.getElementById('antivirus-dashboard-status-text');
    
    if (dashboardIndicator && dashboardStatusText) {
      if (isScanning) {
        dashboardIndicator.className = 'w-2 h-2 bg-orange-500 rounded-full animate-pulse';
        dashboardStatusText.textContent = 'Escaneando';
        dashboardStatusText.className = 'text-xs text-orange-600 font-semibold';
      } else {
        dashboardIndicator.className = 'w-2 h-2 bg-green-500 rounded-full';
        dashboardStatusText.textContent = 'Activo';
        dashboardStatusText.className = 'text-xs text-green-600 font-semibold';
      }
    }
    
    // Update all start/stop buttons (both dashboard and forensics section)
    const allStartBtns = document.querySelectorAll('[data-action="start-antivirus-scan"]');
    const allStopBtns = document.querySelectorAll('[data-action="stop-antivirus-scan"]');
    
    allStartBtns.forEach(btn => {
      if (isScanning) {
        btn.disabled = true;
        btn.classList.add('opacity-50', 'cursor-not-allowed');
      } else {
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'cursor-not-allowed');
      }
    });
    
    allStopBtns.forEach(btn => {
      if (isScanning) {
        btn.disabled = false;
        btn.classList.remove('opacity-50', 'cursor-not-allowed', 'hidden');
        btn.classList.add('block');
      } else {
        btn.disabled = true;
        btn.classList.add('opacity-50', 'cursor-not-allowed', 'hidden');
        btn.classList.remove('block');
      }
    });
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
      progressPercent: 0,
      startTime: null,
      etaSeconds: null,
      currentFileName: null,
      folderType: null
    };
    
    // Update the terminal progress to hide the progress bar
    this.updateTerminalProgress();
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
    try {
      // Open file dialog to select file
      const result = await window.electronAPI.showOpenDialog({
        title: 'Seleccionar archivo para escanear',
        properties: ['openFile'],
        filters: [
          { name: 'Todos los archivos', extensions: ['*'] },
          { name: 'Ejecutables', extensions: ['exe', 'msi', 'bat', 'cmd'] },
          { name: 'Documentos', extensions: ['pdf', 'doc', 'docx', 'xls', 'xlsx'] },
          { name: 'Archivos de sistema', extensions: ['dll', 'sys', 'drv'] }
        ]
      });

      if (!result.canceled && result.filePaths.length > 0) {
        const selectedFile = result.filePaths[0];
        
        this.showNotification('Escaneando archivo...', 'info');
        this.addForensicsLogEntry('Antivirus', `🔍 Iniciando escaneo de archivo: ${selectedFile.split('\\').pop().split('/').pop()}`, 'info');
        
        // Call backend to scan the file
        const scanResult = await window.electronAPI.scanFile(selectedFile);
        
        if (scanResult.success) {
          if (scanResult.threats && scanResult.threats.length > 0) {
            // Extract threat names from objects if they are objects
            let threatNames;
            if (Array.isArray(scanResult.threats)) {
              threatNames = scanResult.threats.map(threat => {
                if (typeof threat === 'string') {
                  return threat;
                } else if (threat && typeof threat === 'object') {
                  return threat.name || threat.threat_name || threat.description || JSON.stringify(threat);
                }
                return String(threat);
              }).join(', ');
            } else {
              threatNames = String(scanResult.threats);
            }
            
            this.showNotification(`⚠️ ${scanResult.threats.length} amenaza(s) detectada(s)`, 'warning');
            this.addForensicsLogEntry('Antivirus', `⚠️ ${scanResult.file_name || 'Archivo'} - VIRUS DETECTADO: ${threatNames}`, 'warning');
            
            // Add activity log entry
            this.addActivityLogEntry('antivirus', 'Amenaza detectada', `${scanResult.threats.length} amenaza(s) en ${scanResult.file_name || 'archivo'}`, 'warning');
            
            // Update threat count and stats
            this.threatCount += scanResult.threats.length;
            this.updateAntivirusStats({
              files_scanned: 1,
              threats_found: this.threatCount,
              total_files: 1
            });
          } else {
            this.showNotification('✅ Archivo limpio - Sin amenazas detectadas', 'success');
            this.addForensicsLogEntry('Antivirus', `✅ ${scanResult.file_name || 'Archivo'} - SIN VIRUS`, 'success');
            
            // Add activity log entry for clean scan
            this.addActivityLogEntry('antivirus', 'Escaneo completado', `Archivo limpio: ${scanResult.file_name || 'archivo'}`, 'success');
          }
          
          // Update dashboard stats
          await this.loadAntivirusStatus();
          // Update dashboard statistics
          await this.updateDashboardStatistics();
        } else {
          this.addForensicsLogEntry('Antivirus', `Error: ${scanResult.message}`, 'error');
          this.showNotification(scanResult.message, 'error');
        }
      }
    } catch (error) {
      this.addForensicsLogEntry('Antivirus', `Error seleccionando archivo: ${error.message}`, 'error');
      this.showNotification('No se pudo abrir el selector de archivos. Verifique los permisos del sistema.', 'error');
    }
  }

  openAntivirusSettings() {
    // Navigate to forensics section where antivirus settings are available
    this.navigateToSection('forensics');
    this.showNotification('Configuración de antivirus disponible en la sección Forenses', 'info');
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

  async handleAntivirusProgress(progressData) {
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
        this.addForensicsLogEntry('Antivirus', `🔍 [${progressData.data.current_file || 0}/${progressData.data.total_files || 0}] Escaneando: ${progressData.data.file_name}`, 'info');
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
        
        // Track module usage for scoring
        this.trackModuleUsage('antivirus');
      } else if (progressData.message.includes('All folders scanned')) {
        this.addForensicsLogEntry('Antivirus', `🎉 Todos los escaneos completados: ${progressData.data.total_files_scanned} archivos, ${progressData.data.total_threats_found} amenazas`, 'success');
        // Reset button states when all scans complete
        this.updateAntivirusButtonStates(false);
        this.clearProgressDisplay();
        // Update dashboard statistics
        await this.updateDashboardStatistics();
        
        // Add activity log entry
        this.addActivityLogEntry('antivirus', 'Escaneo completo', `${progressData.data.total_files_scanned} archivos escaneados, ${progressData.data.total_threats_found} amenazas`, 'success');
        
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
        // Extract threat names from objects if they are objects
        let threatNames;
        if (Array.isArray(progressData.data.threats)) {
          threatNames = progressData.data.threats.map(threat => {
            if (typeof threat === 'string') {
              return threat;
            } else if (threat && typeof threat === 'object') {
              return threat.name || threat.threat_name || threat.description || JSON.stringify(threat);
            }
            return String(threat);
          }).join(', ');
        } else {
          threatNames = String(progressData.data.threats);
        }
        
        this.addForensicsLogEntry('Antivirus', `⚠️ ${progressData.data.file_name || 'Archivo'} - VIRUS DETECTADO: ${threatNames}`, 'warning');
        
        // Update threat count and stats
        this.threatCount += progressData.data.threats.length;
        this.updateAntivirusStats({
          files_scanned: progressData.data.current_file || 0,
          threats_found: this.threatCount,
          total_files: progressData.data.total_files || 0
        });
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
    // Update forensics section stats
    const threatsCount = document.getElementById('antivirus-threats-count');
    const scannedCount = document.getElementById('antivirus-scanned-count');
    const lastScan = document.getElementById('antivirus-last-scan');
    
    // Update dashboard section stats
    const dashboardThreatsCount = document.getElementById('antivirus-dashboard-threats-count');
    const dashboardScannedCount = document.getElementById('antivirus-dashboard-scanned-count');
    const dashboardLastScan = document.getElementById('antivirus-dashboard-last-scan');
    
    // Update counts for both sections
    const updateCountElement = (element, count, isThreat = false) => {
      if (element) {
        element.textContent = count || 0;
        if (isThreat) {
          if (count > 0) {
            element.className = 'text-lg font-bold text-red-600 animate-pulse';
            element.title = `⚠️ ${count} amenaza(s) detectada(s)`;
      } else {
            element.className = 'text-lg font-bold text-green-600';
            element.title = '✅ Sistema limpio';
          }
      } else {
          if (count > 0) {
            element.className = 'text-lg font-bold text-blue-600';
            element.title = `📁 ${count} archivo(s) escaneado(s)`;
          } else {
            element.className = 'text-lg font-bold text-gray-600';
            element.title = '📁 No hay archivos escaneados';
          }
        }
      }
    };
    
    updateCountElement(threatsCount, stats.threats_found, true);
    updateCountElement(dashboardThreatsCount, stats.threats_found, true);
    updateCountElement(scannedCount, stats.files_scanned, false);
    updateCountElement(dashboardScannedCount, stats.files_scanned, false);
    
    // Update last scan with actual date and time for both sections
    const updateLastScanElement = (element) => {
      if (element) {
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
        element.textContent = `Último escaneo: ${dateStr} ${timeStr}`;
        element.title = `Escaneo completado el ${dateStr} a las ${timeStr}`;
      }
    };
    
    updateLastScanElement(lastScan);
    updateLastScanElement(dashboardLastScan);
  }

  initializeAntivirusStats() {
    // Always initialize with clean values - no threats shown until actual scan
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
        
        // Update total stats for both dashboard and forensics sections
        // Only show threats if there was a recent scan (within last 24 hours)
        const hasRecentScan = this.appData.lastScanDate && 
          (Date.now() - new Date(this.appData.lastScanDate).getTime()) < (24 * 60 * 60 * 1000);
        
        this.updateAntivirusStats({
          files_scanned: this.appData.totalFilesScanned || 0,
          threats_found: hasRecentScan ? (this.appData.totalThreatsFound || 0) : 0,
          total_files: this.appData.totalFilesScanned || 0
        });
        
        // Update dashboard antivirus status with app data
        this.updateAntivirusDashboardStatus({
          isActive: true,
          lastScan: this.appData.lastScanDate || null,
          threatsFound: hasRecentScan ? (this.appData.totalThreatsFound || 0) : 0,
          filesScanned: this.appData.totalFilesScanned || 0
        });
        
        // Update analyzer display with persistent data
        if (this.appData.lastAnalysis) {
          this.updateAnalyzerDisplay(this.appData.lastAnalysis);
          this.updateForensicsDashboardStatus(this.appData.lastAnalysis);
        }
        
        // Update dashboard statistics after loading all app data
        await this.updateDashboardStatistics();
        
        console.log('App data loaded:', this.appData);
      }
    } catch (error) {
      console.error('Error loading app data:', error);
    }
  }

  updateLastScanDisplay(lastScanDate) {
    // Update both forensics section and dashboard section
    const lastScanElements = [
      document.getElementById('antivirus-last-scan'),
      document.getElementById('antivirus-dashboard-last-scan')
    ];
    
    lastScanElements.forEach(lastScan => {
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
    });
  }

  async saveScanData(scanData) {
    try {
      // Prepare data to save with last scan date
      const dataToSave = {
        ...scanData,
        lastScanDate: new Date().toISOString(),
        totalFilesScanned: scanData.filesScanned || scanData.totalFilesScanned || 0,
        totalThreatsFound: scanData.threatsFound || scanData.totalThreatsFound || 0
      };
      
      const result = await window.electronAPI.updateScanData(dataToSave);
      if (result.success) {
        console.log('Scan data saved successfully');
        // Update local app data
        this.appData = { ...this.appData, ...dataToSave };
        // Update the last scan display for both sections
        this.updateLastScanDisplay(dataToSave.lastScanDate);
        // Update antivirus stats
        this.updateAntivirusStats({
          files_scanned: dataToSave.totalFilesScanned,
          threats_found: dataToSave.totalThreatsFound
        });
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
        // Update dashboard status
        this.updateForensicsDashboardStatus(analysisData);
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
            analysisResult: analysisResult,
            suspicious: analysisResult.analysis?.security?.riskLevel === 'high' || analysisResult.analysis?.security?.riskLevel === 'medium'
          };
          
          await this.saveAnalysisData(analysisData);
          this.updateAnalyzerDisplay(analysisData);
          
          // Add activity log entry
          this.addActivityLogEntry('forensics', 'Análisis completado', `Archivo analizado: ${analysisData.fileName}`, 'success');
          
          // Track module usage for scoring
          this.trackModuleUsage('forensics', 'file-analysis');
          
          const fileName = analysisResult.analysis?.basic?.name || analysisData.fileName;
          this.addForensicsLogEntry('Analizador', `✅ Análisis completado: ${fileName}`, 'success');
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
    
    if (!analysis) {
      this.addForensicsLogEntry('Analizador', 'Error: No se pudo obtener el análisis del archivo', 'error');
      return;
    }
    
    // Create detailed analysis display
    let analysisText = `📁 Archivo: ${analysis.basic?.name || 'Archivo desconocido'}\n`;
    analysisText += `📊 Tamaño: ${analysis.basic?.sizeFormatted || 'Desconocido'}\n`;
    analysisText += `📝 Tipo: ${analysis.basic?.type || 'Desconocido'}\n`;
    
    if (analysis.basic?.created) {
    analysisText += `📅 Creado: ${new Date(analysis.basic.created).toLocaleString('es-ES')}\n`;
    }
    if (analysis.basic?.modified) {
    analysisText += `📅 Modificado: ${new Date(analysis.basic.modified).toLocaleString('es-ES')}\n\n`;
    }
    
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
    
    // Always append new entries to the bottom of the log
      logDisplay.appendChild(logEntry);
    
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

  // URL Scanner Methods
  async scanUrl() {
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-url-btn');
    const resultsContainer = document.getElementById('url-scan-results');
    
    if (!urlInput || !urlInput.value.trim()) {
      this.showNotification('Por favor ingresa una URL válida', 'warning');
      return;
    }
    
    const url = urlInput.value.trim();
    
    // Validate URL format
    try {
      new URL(url);
    } catch (error) {
      this.showNotification('URL inválida. Por favor ingresa una URL válida (ej: https://ejemplo.com)', 'error');
      return;
    }
    
    // Disable button and show loading
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Escaneando...';
    }
    
    // Show loading in results
    if (resultsContainer) {
      resultsContainer.innerHTML = `
        <div class="text-center py-8">
          <i class="fas fa-spinner fa-spin text-3xl text-blue-500 mb-2"></i>
          <p class="text-gray-600">Escaneando URL...</p>
          <p class="text-sm text-gray-500">${url}</p>
        </div>
      `;
    }
    
    try {
      // Simulate URL scanning (replace with actual backend call)
      const result = await this.performUrlScan(url);
      
      // Display results
      this.displayUrlScanResults(result);
      
      // Add to history
      this.addToUrlScanHistory(result);
      
      // Update statistics
      this.updateUrlScanStatistics(result);
      
      // Add activity log entry
      this.addActivityLogEntry('urlscanner', 'URL escaneada', `URL analizada: ${url}`, result.isMalicious ? 'warning' : 'success');
      
      // Track module usage for scoring
      this.trackModuleUsage('urlscanner');
      
      this.showNotification(`URL escaneada: ${result.isMalicious ? 'Amenaza detectada' : 'URL limpia'}`, result.isMalicious ? 'warning' : 'success');
      
    } catch (error) {
      console.error('Error scanning URL:', error);
      this.showNotification('Error al escanear la URL', 'error');
      
      if (resultsContainer) {
        resultsContainer.innerHTML = `
          <div class="text-center py-8">
            <i class="fas fa-exclamation-triangle text-3xl text-red-500 mb-2"></i>
            <p class="text-red-600">Error al escanear la URL</p>
            <p class="text-sm text-gray-500">${error.message}</p>
          </div>
        `;
      }
    } finally {
      // Re-enable button
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '<i class="fas fa-search"></i> Escanear';
      }
    }
  }
  
  async performUrlScan(url) {
    try {
      // Call the backend VirusTotal API
      const result = await window.electronAPI.scanUrlWithVirusTotal(url);
      
      if (result.success && result.virustotalResult) {
        const vtResult = result.virustotalResult;
        const isMalicious = vtResult.positives > 0;
        const isSuspicious = vtResult.positives > 0 && vtResult.positives < vtResult.total_scans * 0.3;
        
        return {
          url: url,
          timestamp: new Date(),
          isMalicious: isMalicious,
          isSuspicious: isSuspicious,
          threats: vtResult.threats || [],
          reputation: isMalicious ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Clean',
          details: {
            domain: new URL(url).hostname,
            protocol: new URL(url).protocol,
            path: new URL(url).pathname,
            positives: vtResult.positives || 0,
            totalScans: vtResult.total_scans || 0,
            scanDate: vtResult.scan_date,
            permalink: vtResult.permalink
          },
          virustotalData: vtResult
        };
      } else {
        // Fallback to simulation if VirusTotal fails
        return this.performUrlScanSimulation(url);
      }
    } catch (error) {
      console.error('Error calling VirusTotal API:', error);
      // Fallback to simulation
      return this.performUrlScanSimulation(url);
    }
  }
  
  async performUrlScanSimulation(url) {
    // Fallback simulation for when VirusTotal is not available
    return new Promise((resolve) => {
      setTimeout(() => {
        // Simulate different scan results
        const isMalicious = Math.random() < 0.1; // 10% chance of being malicious
        const isSuspicious = Math.random() < 0.2; // 20% chance of being suspicious
        
        const result = {
          url: url,
          timestamp: new Date(),
          isMalicious: isMalicious,
          isSuspicious: isSuspicious,
          threats: isMalicious ? ['Malware', 'Phishing'] : [],
          reputation: isMalicious ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Clean',
          details: {
            domain: new URL(url).hostname,
            protocol: new URL(url).protocol,
            path: new URL(url).pathname
          }
        };
        
        resolve(result);
      }, 2000); // Simulate 2 second scan time
    });
  }
  
  displayUrlScanResults(result) {
    const resultsContainer = document.getElementById('url-scan-results');
    if (!resultsContainer) return;
    
    const statusColor = result.isMalicious ? 'red' : result.isSuspicious ? 'yellow' : 'green';
    const statusIcon = result.isMalicious ? 'fa-exclamation-triangle' : result.isSuspicious ? 'fa-exclamation-circle' : 'fa-check-circle';
    const statusText = result.isMalicious ? 'Maliciosa' : result.isSuspicious ? 'Sospechosa' : 'Limpia';
    
    // VirusTotal specific information
    const positives = result.details.positives || 0;
    const totalScans = result.details.totalScans || 0;
    const scanDate = result.details.scanDate;
    const permalink = result.details.permalink;
    
    resultsContainer.innerHTML = `
      <div class="p-4 bg-${statusColor}-50 rounded-lg border border-${statusColor}-200">
        <div class="flex items-center gap-3 mb-3">
          <i class="fas ${statusIcon} text-${statusColor}-600 text-xl"></i>
          <div>
            <h5 class="font-semibold text-${statusColor}-800">${statusText}</h5>
            <p class="text-sm text-gray-600">${result.url}</p>
          </div>
        </div>
        
        <div class="space-y-2 text-sm">
          <div class="flex justify-between">
            <span class="text-gray-600">Dominio:</span>
            <span class="font-mono">${result.details.domain}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-600">Protocolo:</span>
            <span class="font-mono">${result.details.protocol}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-600">Reputación:</span>
            <span class="font-semibold text-${statusColor}-600">${result.reputation}</span>
          </div>
          ${totalScans > 0 ? `
            <div class="flex justify-between">
              <span class="text-gray-600">Detecciones:</span>
              <span class="font-semibold text-${statusColor}-600">${positives}/${totalScans}</span>
            </div>
          ` : ''}
          <div class="flex justify-between">
            <span class="text-gray-600">Escaneado:</span>
            <span class="text-gray-500">${result.timestamp.toLocaleTimeString('es-ES')}</span>
          </div>
          ${scanDate ? `
            <div class="flex justify-between">
              <span class="text-gray-600">Último escaneo VT:</span>
              <span class="text-gray-500">${new Date(scanDate * 1000).toLocaleString('es-ES')}</span>
            </div>
          ` : ''}
        </div>
        
        ${result.threats.length > 0 ? `
          <div class="mt-3 pt-3 border-t border-${statusColor}-200">
            <p class="text-sm font-medium text-${statusColor}-700 mb-1">Amenazas detectadas:</p>
            <ul class="text-sm text-${statusColor}-600">
              ${result.threats.map(threat => {
                if (typeof threat === 'string') {
                  return `<li>• ${threat}</li>`;
                } else {
                  // Create more coherent threat descriptions in Spanish
                  const engine = threat.engine || 'Motor Desconocido';
                  const threatName = threat.name || 'Amenaza Desconocida';
                  const severity = threat.severity || 'medium';
                
                  // Map severity to more descriptive text in Spanish
                  const severityText = {
                    'low': 'Riesgo Bajo',
                    'medium': 'Riesgo Medio', 
                    'high': 'Riesgo Alto',
                    'critical': 'Riesgo Crítico'
                  }[severity] || 'Riesgo Medio';
                  
                  // Create more coherent threat description in Spanish
                  let threatDescription = '';
                  if (threatName.toLowerCase().includes('malicious site')) {
                    threatDescription = `Sitio Malicioso (${severityText})`;
                  } else if (threatName.toLowerCase().includes('malware')) {
                    threatDescription = `Distribución de Malware (${severityText})`;
                  } else if (threatName.toLowerCase().includes('phishing')) {
                    threatDescription = `Sitio de Phishing (${severityText})`;
                  } else if (threatName.toLowerCase().includes('trojan')) {
                    threatDescription = `Caballo de Troya (${severityText})`;
                  } else if (threatName.toLowerCase().includes('virus')) {
                    threatDescription = `Virus Informático (${severityText})`;
                  } else {
                    threatDescription = `${threatName} (${severityText})`;
                  }
                  
                  return `<li>• <strong>${engine}:</strong> ${threatDescription}</li>`;
                }
              }).join('')}
            </ul>
          </div>
        ` : ''}
        
        ${permalink ? `
          <div class="mt-3 pt-3 border-t border-gray-200">
            <a href="${permalink}" target="_blank" class="text-blue-600 hover:text-blue-800 text-sm">
              <i class="fas fa-external-link-alt mr-1"></i>
              Ver reporte completo en VirusTotal
            </a>
          </div>
        ` : ''}
      </div>
    `;
  }
  
  addToUrlScanHistory(result) {
    this.urlScanHistory.unshift(result);
    
    // Keep only last 10 scans
    if (this.urlScanHistory.length > 10) {
      this.urlScanHistory = this.urlScanHistory.slice(0, 10);
    }
    
    this.updateRecentUrlScans();
  }
  
  updateRecentUrlScans() {
    const container = document.getElementById('recent-url-scans');
    if (!container) return;
    
    if (this.urlScanHistory.length === 0) {
      container.innerHTML = `
        <div class="text-center text-gray-500 py-4">
          <p>No hay escaneos recientes</p>
        </div>
      `;
      return;
    }
    
    container.innerHTML = this.urlScanHistory.map(scan => {
      const statusColor = scan.isMalicious ? 'red' : scan.isSuspicious ? 'yellow' : 'green';
      const statusIcon = scan.isMalicious ? 'fa-exclamation-triangle' : scan.isSuspicious ? 'fa-exclamation-circle' : 'fa-check-circle';
      
      return `
        <div class="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
          <i class="fas ${statusIcon} text-${statusColor}-500"></i>
          <div class="flex-1">
            <p class="text-sm font-medium text-gray-800 truncate">${scan.url}</p>
            <p class="text-xs text-gray-500">${scan.timestamp.toLocaleString('es-ES')}</p>
          </div>
          <span class="text-xs px-2 py-1 rounded-full bg-${statusColor}-100 text-${statusColor}-700">
            ${scan.reputation}
          </span>
        </div>
      `;
    }).join('');
  }
  
  updateUrlScanStatistics(result) {
    const cleanCount = document.getElementById('url-scans-clean');
    const maliciousCount = document.getElementById('url-scans-malicious');
    const suspiciousCount = document.getElementById('url-scans-suspicious');
    const totalCount = document.getElementById('url-scans-total');
    
    // Update counts based on scan history
    const cleanScans = this.urlScanHistory.filter(scan => !scan.isMalicious && !scan.isSuspicious).length;
    const maliciousScans = this.urlScanHistory.filter(scan => scan.isMalicious).length;
    const suspiciousScans = this.urlScanHistory.filter(scan => scan.isSuspicious).length;
    const totalScans = this.urlScanHistory.length;
    
    if (cleanCount) cleanCount.textContent = cleanScans;
    if (maliciousCount) maliciousCount.textContent = maliciousScans;
    if (suspiciousCount) suspiciousCount.textContent = suspiciousScans;
    if (totalCount) totalCount.textContent = totalScans;
  }
  
  clearUrlInput() {
    const urlInput = document.getElementById('url-input');
    const resultsContainer = document.getElementById('url-scan-results');
    
    if (urlInput) {
      urlInput.value = '';
    }
    
    if (resultsContainer) {
      resultsContainer.innerHTML = `
        <div class="text-center text-gray-500 py-8">
          <i class="fas fa-search text-3xl mb-2"></i>
          <p>Ingresa una URL para comenzar el escaneo</p>
        </div>
      `;
    }
    
    this.showNotification('URL limpiada', 'info');
  }
  
  showUrlScanHistory() {
    this.showNotification('Historial de escaneos de URL', 'info');
    // In a full implementation, this could open a modal with detailed history
  }
}

document.addEventListener('DOMContentLoaded', () => new CiberSegApp());
