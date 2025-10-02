# Módulo Antivirus CiberSeg

Este módulo proporciona funcionalidad antivirus utilizando la API de VirusTotal para detección integral de malware.

## Instrucciones de Configuración

### 1. Obtener Clave API de VirusTotal

1. Ve a [VirusTotal](https://www.virustotal.com/)
2. Crea una cuenta gratuita
3. Ve a la configuración de tu perfil
4. Genera una clave API

### 2. Configurar Clave API

Tienes dos opciones para configurar tu clave API:

#### Opción A: Variable de Entorno (Recomendado)
```bash
# Windows
set VIRUSTOTAL_API_KEY=ab84f5f3146a5c18429112267f85a1007d64756dd1940efedaf7d2cf6466ca47

# Linux/Mac
export VIRUSTOTAL_API_KEY=tu_clave_api_aqui
```

#### Opción B: Archivo de Configuración
1. Copia `config.py.example` a `config.py`
2. Reemplaza `ab84f5f3146a5c18429112267f85a1007d64756dd1940efedaf7d2cf6466ca47` con tu clave API real

### 3. Instalar Dependencias

```bash
pip install -r requirements.txt
```

## Uso

### Uso desde Línea de Comandos

```bash
# Escanear un archivo específico
python antivirus.py scan-file --file "ruta/al/archivo.exe"

# Escanear un directorio
python antivirus.py scan --directory "ruta/al/directorio"

# Escaneo rápido del sistema (directorios comunes)
python antivirus.py scan --scan-type quick

# Escanear una URL
python antivirus.py scan-url --url "https://ejemplo.com"

# Escanear un dominio
python antivirus.py scan-domain --domain "ejemplo.com"

# Escanear una dirección IP
python antivirus.py scan-ip --ip "192.168.1.1"

# Obtener estado del antivirus
python antivirus.py status

# Obtener estadísticas de escaneo
python antivirus.py stats

# Limpiar caché de escaneos de URL
python antivirus.py clear-url-cache

# Actualizar base de datos (placeholder)
python antivirus.py update-db
```

### Integración API

El módulo está diseñado para trabajar con el proceso principal de Electron a través de salida JSON.

## Características

- **Escaneo por Hash de Archivo**: Escaneo rápido usando hashes SHA256
- **Escaneo por Subida de Archivo**: Subir archivos para análisis integral
- **Escaneo de Directorios**: Escanear directorios completos recursivamente
- **Escaneo de URLs**: Analizar URLs usando más de 70 motores antivirus
- **Escaneo de Dominios**: Análisis completo de dominios y subdominios
- **Escaneo de IPs**: Verificar direcciones IP contra bases de datos de amenazas
- **Caché Inteligente**: Sistema de caché para evitar escaneos repetidos
- **Resultados en Tiempo Real**: Obtener resultados de escaneo inmediatos
- **Detección de Amenazas**: Identificar malware usando más de 70 motores antivirus
- **Rate Limiting**: Control automático de velocidad de API para cumplir límites
- **Manejo de Errores**: Gestión robusta de errores y reintentos automáticos
- **Seguimiento de Estadísticas**: Rastrear historial de escaneos y estadísticas

## Límites de API

- **Nivel Gratuito**: 4 solicitudes por minuto, 500 solicitudes por día
- **Límite de Tamaño de Archivo**: 32MB tamaño máximo de archivo
- **Limitación de Velocidad**: Retrasos integrados para respetar límites de API

## Manejo de Errores

El módulo incluye manejo integral de errores para:
- Problemas de conectividad de red
- Limitación de velocidad de API
- Errores de acceso a archivos
- Claves API inválidas
- Subidas de archivos grandes

## Notas de Seguridad

- Las claves API se almacenan de forma segura
- Las subidas de archivos son temporales y se eliminan después del escaneo
- No se registran datos sensibles
- Todas las comunicaciones usan HTTPS

## Solución de Problemas

### Problemas Comunes

1. **"No se proporcionó clave API de VirusTotal"**
   - Asegúrate de que tu clave API esté configurada correctamente
   - Verifica las variables de entorno o archivo de configuración

2. **"Archivo demasiado grande"**
   - VirusTotal tiene un límite de tamaño de archivo de 32MB
   - Comprime o divide archivos grandes

3. **"Límite de velocidad de API excedido"**
   - Espera unos minutos antes de reintentar
   - Considera actualizar a un plan pagado de VirusTotal

4. **"Tiempo de espera del escaneo"**
   - Los archivos grandes pueden tardar más en escanearse
   - Verifica tu conexión a internet

### Modo Debug

Habilita el registro de debug estableciendo el nivel de log:
```python
logging.basicConfig(level=logging.DEBUG)
```