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
    
    // Always show terms modal for testing purposes
    this.showTermsModal();
    
    // Show terms modal if not accepted (uncomment when done testing)
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

  // Acciones rápidas (banner puede estar ausente) - no-op si elementos no están presentes
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


    // Toggle del menú móvil
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

    // Terms modal event listeners
    const acceptTermsBtn = document.getElementById('accept-terms');
    const declineTermsBtn = document.getElementById('decline-terms');
    
    if (acceptTermsBtn) {
      acceptTermsBtn.addEventListener('click', () => this.acceptTerms());
    }
    
    if (declineTermsBtn) {
      declineTermsBtn.addEventListener('click', () => this.declineTerms());
    }
  }

  setupButtonInteractions() {
    // Remove duplicate listeners - buttons with data-action are handled elsewhere
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
      // Usar la funcionalidad real del backend
      const result = await window.electronAPI.generatePassword({
        length: 16,
        includeSymbols: true,
        includeNumbers: true
      });
      
      this.showNotification(`Nueva contraseña generada (${result.strength}): ${result.password}`, 'success');
    } catch (error) {
      console.error('Error al generar contraseña:', error);
      // Fallback a la generación local
      const password = this.generateSecurePassword();
      this.showNotification(`Nueva contraseña generada: ${password}`, 'success');
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

  // Terms and Conditions Methods
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
    // Optionally close the app or show a different message
    setTimeout(() => {
      if (confirm('¿Está seguro de que desea rechazar los términos? La aplicación se cerrará.')) {
        // In a real Electron app, you would use window.close() or ipcRenderer
        window.close();
      }
    }, 1000);
  }
}

document.addEventListener('DOMContentLoaded', () => new CiberSegApp());
