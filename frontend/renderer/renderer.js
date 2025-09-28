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
}

document.addEventListener('DOMContentLoaded', () => new CiberSegApp());
