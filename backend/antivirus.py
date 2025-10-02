#!/usr/bin/env python3
"""
Módulo Antivirus CiberSeg
Escáner antivirus basado en Python usando la API de VirusTotal
"""

import os
import sys
import json
import hashlib
import requests
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import threading
import queue

# Intentar importar config, usar variables de entorno como respaldo
try:
    from config import VIRUSTOTAL_API_KEY, MAX_FILE_SIZE_MB, SCAN_TIMEOUT_SECONDS, API_RATE_LIMIT_DELAY
except ImportError:
    # Respaldo a variables de entorno si config.py no existe
    VIRUSTOTAL_API_KEY = None
    MAX_FILE_SIZE_MB = 32
    SCAN_TIMEOUT_SECONDS = 300
    API_RATE_LIMIT_DELAY = 1

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ProgressStreamer:
    """Transmite actualizaciones de progreso a stdout para actualizaciones en tiempo real del frontend"""
    
    def __init__(self):
        self.progress_queue = queue.Queue()
        self.is_streaming = False
    
    def start_streaming(self):
        """Start streaming progress updates"""
        self.is_streaming = True
        self.stream_thread = threading.Thread(target=self._stream_progress, daemon=False)
        self.stream_thread.start()
    
    def stop_streaming(self):
        """Stop streaming progress updates"""
        self.is_streaming = False
        if hasattr(self, 'stream_thread') and self.stream_thread.is_alive():
            self.stream_thread.join(timeout=1.0)
    
    def add_progress(self, message: str, progress_type: str = 'info', data: Dict = None):
        """Add a progress update to the stream"""
        if self.is_streaming:
            progress_data = {
                'timestamp': time.time(),
                'message': message,
                'type': progress_type,
                'data': data or {}
            }
            self.progress_queue.put(progress_data)
    
    def _stream_progress(self):
        """Stream progress updates to stdout"""
        while self.is_streaming:
            try:
                progress_data = self.progress_queue.get(timeout=0.1)
                print(json.dumps(progress_data), flush=True)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error streaming progress: {e}")
                break

class VirusTotalAntivirus:
    """Antivirus scanner using VirusTotal API"""
    
    def __init__(self, api_key: Optional[str] = None, enable_progress_streaming: bool = False):
        """
        Initialize the VirusTotal antivirus scanner
        
        Args:
            api_key: VirusTotal API key. If None, will try to get from config or environment variable
            enable_progress_streaming: Enable real-time progress streaming
        """
        self.api_key = api_key or VIRUSTOTAL_API_KEY or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/vtapi/v2'
        self.max_file_size = MAX_FILE_SIZE_MB * 1024 * 1024  # Convert to bytes
        self.scan_timeout = SCAN_TIMEOUT_SECONDS
        self.rate_limit_delay = API_RATE_LIMIT_DELAY
        self.scan_history = []
        self.url_scan_cache = {}  # Cache for URL scan results
        self.cache_expiry = 3600  # Cache expiry time in seconds (1 hour)
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'last_scan_time': None,
            'api_calls_made': 0,
            'url_scans_cached': 0,
            'url_scans_performed': 0
        }
        
        # Progress streaming
        self.progress_streamer = ProgressStreamer() if enable_progress_streaming else None
        if self.progress_streamer:
            self.progress_streamer.start_streaming()
        
        # Disable regular logging when progress streaming is enabled
        if enable_progress_streaming:
            logger.setLevel(logging.ERROR)  # Only show errors, not info messages
        
    def cleanup(self):
        """Clean up resources"""
        if self.progress_streamer:
            self.progress_streamer.stop_streaming()
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()
    
    def _send_progress(self, message: str, progress_type: str = 'info', data: Dict = None):
        """Send progress update if streaming is enabled"""
        if self.progress_streamer:
            self.progress_streamer.add_progress(message, progress_type, data)
    
    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        """Check if cache entry is still valid"""
        if not cache_entry or 'timestamp' not in cache_entry:
            return False
        
        current_time = time.time()
        return (current_time - cache_entry['timestamp']) < self.cache_expiry
    
    def _get_cached_result(self, url: str) -> Optional[Dict]:
        """Get cached result for URL if valid"""
        if url in self.url_scan_cache:
            cache_entry = self.url_scan_cache[url]
            if self._is_cache_valid(cache_entry):
                self.stats['url_scans_cached'] += 1
                return cache_entry['result']
            else:
                # Remove expired cache entry
                del self.url_scan_cache[url]
        return None
    
    def _cache_result(self, url: str, result: Dict):
        """Cache scan result for URL"""
        self.url_scan_cache[url] = {
            'result': result,
            'timestamp': time.time()
        }
    
    def get_file_hash(self, file_path: str, hash_type: str = 'sha256') -> str:
        """
        Calculate hash of a file
        
        Args:
            file_path: Path to the file
            hash_type: Type of hash to calculate (md5, sha1, sha256)
            
        Returns:
            Hash string
        """
        try:
            # Normalize the file path
            normalized_path = os.path.normpath(file_path)
            
            if not os.path.exists(normalized_path):
                logger.error(f"File does not exist: {normalized_path}")
                return ""
            
            hash_obj = hashlib.new(hash_type)
            with open(normalized_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def scan_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Scan a file hash using VirusTotal API
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Scan results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            url = f"{self.base_url}/file/report"
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=30)
            self.stats['api_calls_made'] += 1
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('response_code') == 1:  # File found in VirusTotal
                    scans = result.get('scans', {})
                    positives = result.get('positives', 0)
                    total_scans = result.get('total', 0)
                    scan_date = result.get('scan_date')
                    
                    threats = []
                    if positives > 0:
                        for engine, scan_result in scans.items():
                            if scan_result.get('detected'):
                                threats.append({
                                    'engine': engine,
                                    'threat_name': scan_result.get('result', 'Unknown'),
                                    'version': scan_result.get('version', 'Unknown'),
                                    'update_date': scan_result.get('update', 'Unknown')
                                })
                    
                    return {
                        'success': True,
                        'file_hash': file_hash,
                        'positives': positives,
                        'total_scans': total_scans,
                        'threats': threats,
                        'scan_date': scan_date,
                        'permalink': result.get('permalink', ''),
                        'scan_id': result.get('scan_id', '')
                    }
                else:
                    return {
                        'success': True,
                        'file_hash': file_hash,
                        'message': 'Archivo no encontrado en la base de datos de VirusTotal',
                        'threats': [],
                        'scan_date': None
                    }
            else:
                return {
                    'success': False,
                    'message': f'API Error: {response.status_code}',
                    'threats': [],
                    'scan_date': None
                }
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return {
                'success': False,
                'message': f'Request error: {e}',
                'threats': [],
                'scan_date': None
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return {
                'success': False,
                'message': f'Unexpected error: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def upload_and_scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Upload a file to VirusTotal for scanning
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Scan results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            if not os.path.exists(file_path):
                return {
                    'success': False,
                    'message': 'Archivo no encontrado',
                    'threats': [],
                    'scan_date': None
                }
            
            # Check file size (configurable limit)
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return {
                    'success': False,
                    'message': f'File too large (max {MAX_FILE_SIZE_MB}MB)',
                    'threats': [],
                    'scan_date': None
                }
            
            url = f"{self.base_url}/file/scan"
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                params = {'apikey': self.api_key}
                
                response = requests.post(url, files=files, params=params, timeout=60)
                self.stats['api_calls_made'] += 1
                
                # Rate limiting
                time.sleep(self.rate_limit_delay)
            
            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('scan_id')
                
                # Wait for scan to complete and get results
                return self.get_scan_results(scan_id)
            else:
                return {
                    'success': False,
                    'message': f'Upload error: {response.status_code}',
                    'threats': [],
                    'scan_date': None
                }
                
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            return {
                'success': False,
                'message': f'Upload error: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Get scan results for a scan ID
        
        Args:
            scan_id: VirusTotal scan ID
            
        Returns:
            Scan results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            url = f"{self.base_url}/file/report"
            params = {
                'apikey': self.api_key,
                'resource': scan_id
            }
            
            # Poll for results (max 5 minutes)
            max_attempts = 30
            attempt = 0
            
            while attempt < max_attempts:
                response = requests.get(url, params=params, timeout=30)
                self.stats['api_calls_made'] += 1
                
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get('response_code') == 1:  # Scan complete
                        scans = result.get('scans', {})
                        positives = result.get('positives', 0)
                        total_scans = result.get('total', 0)
                        scan_date = result.get('scan_date')
                        
                        threats = []
                        if positives > 0:
                            for engine, scan_result in scans.items():
                                if scan_result.get('detected'):
                                    threats.append({
                                        'engine': engine,
                                        'threat_name': scan_result.get('result', 'Unknown'),
                                        'version': scan_result.get('version', 'Unknown'),
                                        'update_date': scan_result.get('update', 'Unknown')
                                    })
                        
                        return {
                            'success': True,
                            'scan_id': scan_id,
                            'positives': positives,
                            'total_scans': total_scans,
                            'threats': threats,
                            'scan_date': scan_date,
                            'permalink': result.get('permalink', '')
                        }
                    elif result.get('response_code') == -2:  # Still scanning
                        time.sleep(10)  # Wait 10 seconds before next attempt
                        attempt += 1
                        continue
                    else:
                        return {
                            'success': False,
                            'message': 'Scan not found or failed',
                            'threats': [],
                            'scan_date': None
                        }
                else:
                    return {
                        'success': False,
                        'message': f'API error: {response.status_code}',
                        'threats': [],
                        'scan_date': None
                    }
            
            return {
                'success': False,
                'message': 'Scan timeout - results not available',
                'threats': [],
                'scan_date': None
            }
            
        except Exception as e:
            logger.error(f"Error getting scan results: {e}")
            return {
                'success': False,
                'message': f'Error getting scan results: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def _check_suspicious_patterns(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Check for suspicious patterns in files
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            Suspicious pattern detection result or None if not suspicious
        """
        try:
            # Normalize the file path
            normalized_path = os.path.normpath(file_path)
            
            if not os.path.exists(normalized_path):
                return None
            
            file_name = os.path.basename(normalized_path).lower()
            file_ext = os.path.splitext(normalized_path)[1].lower()
            
            threats = []
            
            # Check suspicious file names
            suspicious_names = ['virus', 'malware', 'trojan', 'backdoor', 'rootkit', 'keylogger', 'suspicious', 'testfile']
            if any(name in file_name for name in suspicious_names):
                threats.append({
                    'name': 'Nombre de archivo sospechoso',
                    'severity': 'high',
                    'engine': 'Análisis Heurístico',
                    'description': f'El nombre del archivo contiene palabras clave sospechosas: {file_name}'
                })
            
            # Check suspicious extensions (but exclude common legitimate executables)
            suspicious_extensions = ['.bat', '.cmd', '.ps1', '.vbs', '.js', '.com', '.scr']
            # Only flag .exe files if they have suspicious names or are in suspicious locations
            if file_ext == '.exe':
                # Check for suspicious executable names or locations
                suspicious_exe_names = ['virus', 'malware', 'trojan', 'backdoor', 'rootkit', 'keylogger', 'suspicious', 'testfile', 'hack', 'crack', 'keygen']
                suspicious_exe_locations = ['temp', 'tmp', 'downloads', 'desktop']
                
                if any(name in file_name for name in suspicious_exe_names):
                    threats.append({
                        'name': 'Ejecutable sospechoso',
                        'severity': 'high',
                        'engine': 'Análisis Heurístico',
                        'description': f'Ejecutable con nombre sospechoso: {file_name}'
                    })
                elif any(location in normalized_path.lower() for location in suspicious_exe_locations):
                    threats.append({
                        'name': 'Ejecutable en ubicación sospechosa',
                        'severity': 'medium',
                        'engine': 'Análisis Heurístico',
                        'description': f'Ejecutable encontrado en ubicación sospechosa: {normalized_path}'
                    })
            elif file_ext in suspicious_extensions:
                threats.append({
                    'name': 'Tipo de archivo sospechoso',
                    'severity': 'medium',
                    'engine': 'Análisis Heurístico',
                    'description': f'El archivo tiene una extensión potencialmente peligrosa: {file_ext}'
                })
            
            # Check file content for suspicious patterns
            try:
                with open(normalized_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read().lower()
                
                # Suspicious patterns in scripts
                suspicious_patterns = [
                    ('netstat', 'Network scanning commands'),
                    ('tasklist', 'Process enumeration'),
                    ('reg add', 'Registry modification'),
                    ('del /f', 'Force file deletion'),
                    ('format', 'Disk formatting'),
                    ('shutdown', 'System shutdown'),
                    ('wmic', 'Windows Management Instrumentation'),
                    ('powershell', 'PowerShell execution'),
                    ('cmd /c', 'Command execution'),
                    ('rundll32', 'DLL execution')
                ]
                
                for pattern, description in suspicious_patterns:
                    if pattern in content:
                        threats.append({
                            'name': f'Patrón sospechoso: {pattern}',
                            'severity': 'medium',
                            'engine': 'Análisis Heurístico',
                            'description': description
                        })
                
                # Check for obfuscated code patterns
                if any(char in content for char in ['%random%', '%temp%', 'base64', 'encoded']):
                    threats.append({
                        'name': 'Patrones de código ofuscado',
                        'severity': 'high',
                        'engine': 'Análisis Heurístico',
                        'description': 'El archivo contiene técnicas de ofuscación'
                    })
                
            except Exception:
                # File might be binary or unreadable
                pass
            
            # Check file size for suspicious executables
            if file_ext in ['.exe', '.com', '.scr']:
                file_size = os.path.getsize(normalized_path)
                if file_size < 1000:  # Very small executable
                    threats.append({
                        'name': 'Ejecutable sospechosamente pequeño',
                        'severity': 'high',
                        'engine': 'Análisis Heurístico',
                        'description': f'El archivo ejecutable es inusualmente pequeño ({file_size} bytes)'
                    })
            
            if threats:
                return {
                    'success': True,
                    'file_path': normalized_path,
                    'file_hash': self.get_file_hash(normalized_path, 'sha256'),
                    'message': f'Patrones sospechosos detectados: {len(threats)} amenazas',
                    'threats': threats,
                    'scan_date': time.time()
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking suspicious patterns in {file_path}: {e}")
            return None

    def _check_eicar_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Check if file is an EICAR test file
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            EICAR detection result or None if not EICAR
        """
        try:
            # Normalize the file path
            normalized_path = os.path.normpath(file_path)
            
            if not os.path.exists(normalized_path):
                return None
            
            # Check file size first (EICAR is around 63-68 bytes depending on encoding)
            file_size = os.path.getsize(normalized_path)
            if file_size < 60 or file_size > 80:  # Allow some flexibility
                return None
            
            # Read file content with different encodings
            content = None
            for encoding in ['utf-8', 'utf-8-sig', 'ascii', 'latin-1']:
                try:
                    with open(normalized_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read().strip()
                    break
                except:
                    continue
            
            if not content:
                return None
            
            # Check for EICAR signature (flexible matching)
            eicar_signature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            eicar_signature2 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}-STANDARD-ANTIVIRUS-TEST-FILE!+H*"
            if (eicar_signature in content or 
                eicar_signature2 in content or 
                "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content or
                "STANDARD-ANTIVIRUS-TEST-FILE" in content):
                return {
                    'success': True,
                    'file_path': normalized_path,
                    'file_hash': self.get_file_hash(normalized_path, 'sha256'),
                    'message': 'EICAR test file detected',
                    'threats': [{
                        'name': 'EICAR Test File',
                        'severity': 'critical',
                        'engine': 'EICAR Detection',
                        'description': 'Standard antivirus test file - completely safe'
                    }],
                    'scan_date': time.time()
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking EICAR file {file_path}: {e}")
            return None

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file using VirusTotal
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Scan results dictionary
        """
        try:
            logger.info(f"Scanning file: {file_path}")
            self._send_progress(f"Scanning file: {os.path.basename(file_path)}", 'info', {
                'file_path': file_path,
                'file_name': os.path.basename(file_path)
            })
            
            # Check for EICAR test file first
            eicar_result = self._check_eicar_file(file_path)
            if eicar_result:
                self.stats['files_scanned'] += 1
                self.stats['threats_found'] += len(eicar_result['threats'])
                self.stats['last_scan_time'] = time.time()
                
                self._send_progress("EICAR test file detected!", 'warning', {
                    'threats': eicar_result['threats']
                })
                
                return eicar_result
            
            # Check for suspicious patterns (but don't return immediately - let VirusTotal have priority)
            suspicious_result = self._check_suspicious_patterns(file_path)
            
            # Calculate file hash
            self._send_progress("Calculating file hash...", 'info')
            file_hash = self.get_file_hash(file_path, 'sha256')
            if not file_hash:
                self._send_progress("Error al calcular el hash del archivo", 'error')
                return {
                    'success': False,
                    'message': 'No se pudo calcular el hash del archivo',
                    'file_path': file_path,
                    'threats': [],
                    'scan_date': None
                }
            
            # Try hash-based scan first (faster)
            self._send_progress("Checking VirusTotal database...", 'info')
            result = self.scan_file_hash(file_hash)
            
            if result['success'] and result.get('threats'):
                # File already scanned and has threats
                self.stats['files_scanned'] += 1
                self.stats['threats_found'] += len(result['threats'])
                self.stats['last_scan_time'] = time.time()
                
                self._send_progress(f"Threats found: {len(result['threats'])}", 'warning', {
                    'threats': result['threats']
                })
                
                result['file_path'] = file_path
                result['file_hash'] = file_hash
                result['scan_method'] = 'hash'
                
                self.scan_history.append(result)
                return result
            
            elif result['success'] and not result.get('threats'):
                # File scanned but no threats found by VirusTotal
                # Check if heuristic detection found anything
                if suspicious_result and suspicious_result.get('threats'):
                    # VirusTotal says clean, but heuristic found suspicious patterns
                    # Use heuristic results but mark as low confidence
                    self.stats['files_scanned'] += 1
                    self.stats['threats_found'] += len(suspicious_result['threats'])
                    self.stats['last_scan_time'] = time.time()
                    
                    self._send_progress(f"Patrones sospechosos detectados (VirusTotal limpio): {len(suspicious_result['threats'])} amenazas", 'warning', {
                        'threats': suspicious_result['threats'],
                        'confidence': 'low'
                    })
                    
                    suspicious_result['file_path'] = file_path
                    suspicious_result['file_hash'] = file_hash
                    suspicious_result['scan_method'] = 'heuristic'
                    suspicious_result['virustotal_result'] = 'clean'
                    
                    self.scan_history.append(suspicious_result)
                    return suspicious_result
                else:
                    # Both VirusTotal and heuristic say clean
                    self.stats['files_scanned'] += 1
                    self.stats['last_scan_time'] = time.time()
                    
                    self._send_progress("File is clean", 'success')
                    
                    result['file_path'] = file_path
                    result['file_hash'] = file_hash
                    result['scan_method'] = 'hash'
                    
                    self.scan_history.append(result)
                    return result
            
            else:
                # File not in database, try uploading
                self._send_progress("File not in database, uploading for analysis...", 'info')
                logger.info(f"File not in VirusTotal database, uploading: {file_path}")
                result = self.upload_and_scan_file(file_path)
                
                if result['success']:
                    self.stats['files_scanned'] += 1
                    if result.get('threats'):
                        self.stats['threats_found'] += len(result['threats'])
                        self._send_progress(f"Threats found after upload: {len(result['threats'])}", 'warning', {
                            'threats': result['threats']
                        })
                    else:
                        self._send_progress("File is clean after upload", 'success')
                    self.stats['last_scan_time'] = time.time()
                    
                    result['file_path'] = file_path
                    result['file_hash'] = file_hash
                    result['scan_method'] = 'upload'
                    
                    self.scan_history.append(result)
                    return result
                else:
                    # Upload failed, fall back to heuristic detection
                    if suspicious_result and suspicious_result.get('threats'):
                        self.stats['files_scanned'] += 1
                        self.stats['threats_found'] += len(suspicious_result['threats'])
                        self.stats['last_scan_time'] = time.time()
                        
                        self._send_progress(f"VirusTotal falló, usando detección heurística: {len(suspicious_result['threats'])} amenazas", 'warning', {
                            'threats': suspicious_result['threats'],
                            'confidence': 'medium'
                        })
                        
                        suspicious_result['file_path'] = file_path
                        suspicious_result['file_hash'] = file_hash
                        suspicious_result['scan_method'] = 'heuristic_fallback'
                        suspicious_result['virustotal_error'] = result.get('message', 'Upload failed')
                        
                        self.scan_history.append(suspicious_result)
                        return suspicious_result
                    else:
                        # Both VirusTotal and heuristic failed
                        return {
                            'success': False,
                            'message': f'VirusTotal upload failed: {result.get("message", "Unknown error")}',
                            'file_path': file_path,
                            'threats': [],
                            'scan_date': None
                        }
                
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return {
                'success': False,
                'message': f'Error scanning file: {e}',
                'file_path': file_path,
                'threats': [],
                'scan_date': None
            }
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> Dict[str, Any]:
        """
        Scan all files in a directory
        
        Args:
            directory_path: Path to the directory
            recursive: Whether to scan subdirectories
            
        Returns:
            Scan results dictionary
        """
        try:
            logger.info(f"Scanning directory: {directory_path}")
            start_time = time.time()
            self._send_progress(f"Starting directory scan: {directory_path}", 'info', {
                'directory_path': directory_path,
                'recursive': recursive,
                'start_time': start_time
            })
            
            if not os.path.exists(directory_path):
                self._send_progress("Directory not found", 'error')
                return {
                    'success': False,
                    'message': 'Directory not found',
                    'files_scanned': 0,
                    'threats_found': 0,
                    'results': []
                }
            
            results = []
            files_scanned = 0
            threats_found = 0
            
            # Count total files first for progress tracking
            if recursive:
                pattern = "**/*"
            else:
                pattern = "*"
            
            total_files = sum(1 for f in Path(directory_path).glob(pattern) if f.is_file())
            self._send_progress(f"Found {total_files} files to scan", 'info', {
                'total_files': total_files,
                'start_time': start_time
            })
            
            current_file = 0
            scan_times = []  # Track individual file scan times for ETA calculation
            
            for file_path in Path(directory_path).glob(pattern):
                if file_path.is_file():
                    current_file += 1
                    file_start_time = time.time()
                    
                    # Calculate ETA based on average scan time
                    eta_seconds = None
                    if scan_times and len(scan_times) > 0:
                        avg_scan_time = sum(scan_times) / len(scan_times)
                        remaining_files = total_files - current_file + 1
                        eta_seconds = int(avg_scan_time * remaining_files)
                    
                    self._send_progress(f"Scanning file {current_file}/{total_files}: {file_path.name}", 'info', {
                        'current_file': current_file,
                        'total_files': total_files,
                        'file_name': file_path.name,
                        'file_path': str(file_path),
                        'progress_percent': int((current_file / total_files) * 100),
                        'eta_seconds': eta_seconds,
                        'elapsed_time': int(time.time() - start_time)
                    })
                    
                    try:
                        result = self.scan_file(str(file_path))
                        results.append(result)
                        files_scanned += 1
                        
                        # Track scan time for ETA calculation
                        file_scan_time = time.time() - file_start_time
                        scan_times.append(file_scan_time)
                        
                        if result.get('success') and result.get('threats'):
                            threats_found += len(result['threats'])
                            self._send_progress(f"Threats found in {file_path.name}: {len(result['threats'])}", 'warning', {
                                'file_name': file_path.name,
                                'threats': result['threats'],
                                'scan_time': file_scan_time
                            })
                            
                    except Exception as e:
                        logger.error(f"Error scanning {file_path}: {e}")
                        self._send_progress(f"Error scanning {file_path.name}: {e}", 'error')
                        results.append({
                            'success': False,
                            'file_path': str(file_path),
                            'message': f'Error: {e}',
                            'threats': []
                        })
            
            self._send_progress(f"Directory scan completed: {files_scanned} files scanned, {threats_found} threats found", 'success', {
                'files_scanned': files_scanned,
                'threats_found': threats_found,
                'directory_path': directory_path
            })
            
            return {
                'success': True,
                'directory_path': directory_path,
                'files_scanned': files_scanned,
                'threats_found': threats_found,
                'results': results,
                'scan_time': time.time()
            }
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
            self._send_progress(f"Error scanning directory: {e}", 'error')
            return {
                'success': False,
                'message': f'Error scanning directory: {e}',
                'files_scanned': 0,
                'threats_found': 0,
                'results': []
            }
        finally:
            # Clean up progress streaming
            if self.progress_streamer:
                self.progress_streamer.stop_streaming()
    
    def scan_selected_folders(self, folder_paths: List[str], recursive: bool = True) -> Dict[str, Any]:
        """
        Scan multiple selected folders
        
        Args:
            folder_paths: List of folder paths to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            Combined scan results dictionary
        """
        try:
            start_time = time.time()
            self._send_progress(f"Starting scan of {len(folder_paths)} selected folders", 'info', {
                'folder_count': len(folder_paths),
                'recursive': recursive,
                'start_time': start_time
            })
            
            all_results = []
            total_files_scanned = 0
            total_threats_found = 0
            folder_scan_times = []
            
            for i, folder_path in enumerate(folder_paths):
                folder_start_time = time.time()
                
                # Calculate ETA based on average folder scan time
                eta_seconds = None
                if folder_scan_times and len(folder_scan_times) > 0:
                    avg_folder_time = sum(folder_scan_times) / len(folder_scan_times)
                    remaining_folders = len(folder_paths) - i
                    eta_seconds = int(avg_folder_time * remaining_folders)
                
                self._send_progress(f"Scanning folder {i+1}/{len(folder_paths)}: {folder_path}", 'info', {
                    'current_folder': i+1,
                    'total_folders': len(folder_paths),
                    'folder_path': folder_path,
                    'progress_percent': int(((i + 1) / len(folder_paths)) * 100),
                    'eta_seconds': eta_seconds,
                    'elapsed_time': int(time.time() - start_time)
                })
                
                result = self.scan_directory(folder_path, recursive)
                folder_scan_time = time.time() - folder_start_time
                folder_scan_times.append(folder_scan_time)
                
                if result['success']:
                    all_results.extend(result['results'])
                    total_files_scanned += result['files_scanned']
                    total_threats_found += result['threats_found']
                else:
                    self._send_progress(f"Error al escanear carpeta: {folder_path}", 'error')
            
            total_time = time.time() - start_time
            self._send_progress(f"All folders scanned: {total_files_scanned} files, {total_threats_found} threats", 'success', {
                'total_files_scanned': total_files_scanned,
                'total_threats_found': total_threats_found,
                'folders_scanned': len(folder_paths),
                'total_time': int(total_time)
            })
            
            return {
                'success': True,
                'folders_scanned': len(folder_paths),
                'files_scanned': total_files_scanned,
                'threats_found': total_threats_found,
                'results': all_results,
                'scan_time': time.time(),
                'total_duration': total_time
            }
            
        except Exception as e:
            logger.error(f"Error scanning selected folders: {e}")
            self._send_progress(f"Error scanning selected folders: {e}", 'error')
            return {
                'success': False,
                'message': f'Error scanning selected folders: {e}',
                'files_scanned': 0,
                'threats_found': 0,
                'results': []
            }
        finally:
            # Clean up progress streaming
            if self.progress_streamer:
                self.progress_streamer.stop_streaming()
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL using VirusTotal API with caching
        
        Args:
            url: URL to scan
            
        Returns:
            Scan results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            # Check cache first
            cached_result = self._get_cached_result(url)
            if cached_result:
                cached_result['cached'] = True
                return cached_result
            
            # First check if URL already has a report
            report_result = self.get_url_report(url)
            
            if report_result['success'] and report_result.get('scan_date'):
                # URL already scanned, cache and return existing report
                report_result['cached'] = False
                self._cache_result(url, report_result)
                self.stats['url_scans_performed'] += 1
                return report_result
            
            # If no existing report, submit URL for scanning
            scan_result = self.submit_url_for_scanning(url)
            if scan_result['success']:
                scan_result['cached'] = False
                self._cache_result(url, scan_result)
                self.stats['url_scans_performed'] += 1
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error scanning URL: {e}")
            return {
                'success': False,
                'message': f'URL scan error: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        """
        Get existing URL report from VirusTotal
        
        Args:
            url: URL to check
            
        Returns:
            Report results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            url_endpoint = f"{self.base_url}/url/report"
            params = {
                'apikey': self.api_key,
                'resource': url
            }
            
            response = requests.get(url_endpoint, params=params, timeout=30)
            self.stats['api_calls_made'] += 1
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('response_code') == 1:  # URL found in database
                    threats = []
                    positives = result.get('positives', 0)
                    total_scans = result.get('total', 0)
                    
                    if positives > 0:
                        scans = result.get('scans', {})
                        for engine, scan_result in scans.items():
                            if scan_result.get('detected'):
                                threats.append({
                                    'engine': engine,
                                    'name': scan_result.get('result', 'Unknown threat'),
                                    'severity': 'high' if positives > total_scans * 0.5 else 'medium'
                                })
                    
                    return {
                        'success': True,
                        'url': url,
                        'threats': threats,
                        'scan_date': result.get('scan_date'),
                        'positives': positives,
                        'total_scans': total_scans,
                        'permalink': result.get('permalink'),
                        'message': f'URL report retrieved (detected by {positives}/{total_scans} engines)'
                    }
                else:
                    return {
                        'success': True,
                        'url': url,
                        'threats': [],
                        'scan_date': None,
                        'positives': 0,
                        'total_scans': 0,
                        'message': 'URL not found in VirusTotal database'
                    }
            else:
                return {
                    'success': False,
                    'message': f'API error: {response.status_code}',
                    'threats': [],
                    'scan_date': None
                }
                
        except Exception as e:
            logger.error(f"Error getting URL report: {e}")
            return {
                'success': False,
                'message': f'Report error: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def submit_url_for_scanning(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning to VirusTotal
        
        Args:
            url: URL to submit for scanning
            
        Returns:
            Submission results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            url_endpoint = f"{self.base_url}/url/scan"
            params = {
                'apikey': self.api_key,
                'url': url
            }
            
            response = requests.post(url_endpoint, params=params, timeout=30)
            self.stats['api_calls_made'] += 1
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            if response.status_code == 200:
                result = response.json()
                scan_id = result.get('scan_id')
                
                if scan_id:
                    # Wait a moment for scan to process, then get results
                    time.sleep(2)
                    return self.get_url_report(url)
                else:
                    return {
                        'success': False,
                        'message': 'Failed to get scan ID',
                        'threats': [],
                        'scan_date': None
                    }
            else:
                return {
                    'success': False,
                    'message': f'Submission error: {response.status_code}',
                    'threats': [],
                    'scan_date': None
                }
                
        except Exception as e:
            logger.error(f"Error submitting URL for scanning: {e}")
            return {
                'success': False,
                'message': f'Submission error: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Scan a domain using VirusTotal API
        
        Args:
            domain: Domain to scan
            
        Returns:
            Domain scan results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            url_endpoint = f"{self.base_url}/domain/report"
            params = {
                'apikey': self.api_key,
                'domain': domain
            }
            
            response = requests.get(url_endpoint, params=params, timeout=30)
            self.stats['api_calls_made'] += 1
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            if response.status_code == 200:
                result = response.json()
                
                threats = []
                if result.get('detected_urls'):
                    for detected_url in result['detected_urls']:
                        threats.append({
                            'type': 'malicious_url',
                            'url': detected_url.get('url'),
                            'positives': detected_url.get('positives', 0),
                            'total_scans': detected_url.get('total', 0),
                            'scan_date': detected_url.get('scan_date')
                        })
                
                return {
                    'success': True,
                    'domain': domain,
                    'threats': threats,
                    'scan_date': result.get('scan_date'),
                    'detected_urls_count': len(result.get('detected_urls', [])),
                    'subdomains': result.get('subdomains', []),
                    'resolutions': result.get('resolutions', []),
                    'message': f'Domain analysis completed'
                }
            else:
                return {
                    'success': False,
                    'message': f'Domain scan error: {response.status_code}',
                    'threats': [],
                    'scan_date': None
                }
                
        except Exception as e:
            logger.error(f"Error scanning domain: {e}")
            return {
                'success': False,
                'message': f'Domain scan error: {e}',
                'threats': [],
                'scan_date': None
            }
    
    def scan_ip_address(self, ip_address: str) -> Dict[str, Any]:
        """
        Scan an IP address using VirusTotal API
        
        Args:
            ip_address: IP address to scan
            
        Returns:
            IP scan results dictionary
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'No VirusTotal API key provided',
                'threats': [],
                'scan_date': None
            }
        
        try:
            url_endpoint = f"{self.base_url}/ip-address/report"
            params = {
                'apikey': self.api_key,
                'ip': ip_address
            }
            
            response = requests.get(url_endpoint, params=params, timeout=30)
            self.stats['api_calls_made'] += 1
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            if response.status_code == 200:
                result = response.json()
                
                threats = []
                if result.get('detected_urls'):
                    for detected_url in result['detected_urls']:
                        threats.append({
                            'type': 'malicious_url',
                            'url': detected_url.get('url'),
                            'positives': detected_url.get('positives', 0),
                            'total_scans': detected_url.get('total', 0),
                            'scan_date': detected_url.get('scan_date')
                        })
                
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'threats': threats,
                    'scan_date': result.get('scan_date'),
                    'detected_urls_count': len(result.get('detected_urls', [])),
                    'country': result.get('country'),
                    'asn': result.get('asn'),
                    'resolutions': result.get('resolutions', []),
                    'message': f'IP address analysis completed'
                }
            else:
                return {
                    'success': False,
                    'message': f'IP scan error: {response.status_code}',
                    'threats': [],
                    'scan_date': None
                }
                
        except Exception as e:
            logger.error(f"Error scanning IP address: {e}")
            return {
                'success': False,
                'message': f'IP scan error: {e}',
                'threats': [],
                'scan_date': None
            }

    
    def get_status(self) -> Dict[str, Any]:
        """Get antivirus status"""
        return {
            'success': True,
            'api_key_configured': bool(self.api_key),
            'stats': self.stats,
            'scan_history_count': len(self.scan_history),
            'last_scan_time': self.stats['last_scan_time']
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get antivirus statistics"""
        return {
            'success': True,
            'stats': self.stats,
            'scan_history': self.scan_history[-10:],  # Last 10 scans
            'url_cache_size': len(self.url_scan_cache),
            'cache_expiry_hours': self.cache_expiry / 3600
        }
    
    def clear_url_cache(self) -> Dict[str, Any]:
        """Clear URL scan cache"""
        cache_size = len(self.url_scan_cache)
        self.url_scan_cache.clear()
        return {
            'success': True,
            'message': f'Cleared {cache_size} cached URL scan results',
            'cache_size_before': cache_size,
            'cache_size_after': 0
        }
    
    def update_database(self) -> Dict[str, Any]:
        """Update antivirus database (placeholder for VirusTotal)"""
        return {
            'success': True,
            'message': 'VirusTotal database is automatically updated',
            'timestamp': time.time()
        }

def main():
    """Main function for command line usage"""
    parser = argparse.ArgumentParser(description='CiberSeg Antivirus Scanner')
    parser.add_argument('action', choices=['scan', 'scan-file', 'scan-folders', 'scan-url', 'scan-domain', 'scan-ip', 'status', 'stats', 'update-db', 'clear-url-cache'],
                       help='Action to perform')
    parser.add_argument('--url', help='URL to scan')
    parser.add_argument('--domain', help='Domain to scan')
    parser.add_argument('--ip', help='IP address to scan')
    parser.add_argument('--file', help='File path to scan')
    parser.add_argument('--directory', help='Directory path to scan')
    parser.add_argument('--folders', nargs='+', help='Multiple folder paths to scan')
    parser.add_argument('--api-key', help='VirusTotal API key')
    parser.add_argument('--scan-type', default='quick', help='Scan type (quick/full)')
    parser.add_argument('--enable-progress', action='store_true', help='Enable real-time progress streaming')
    
    args = parser.parse_args()
    
    # Initialize antivirus with progress streaming if enabled
    antivirus = VirusTotalAntivirus(args.api_key, enable_progress_streaming=args.enable_progress)
    
    try:
        if args.action == 'scan':
            if args.directory:
                result = antivirus.scan_directory(args.directory)
            else:
                # Default system scan (scan common directories)
                common_dirs = [
                    os.path.expanduser('~/Downloads'),
                    os.path.expanduser('~/Desktop'),
                    os.path.expanduser('~/Documents')
                ]
                
                all_results = []
                total_files = 0
                total_threats = 0
                
                for directory in common_dirs:
                    if os.path.exists(directory):
                        result = antivirus.scan_directory(directory, recursive=False)
                        if result['success']:
                            all_results.extend(result['results'])
                            total_files += result['files_scanned']
                            total_threats += result['threats_found']
                
                result = {
                    'success': True,
                    'scan_type': args.scan_type,
                    'files_scanned': total_files,
                    'threats_found': total_threats,
                    'results': all_results,
                    'scan_time': time.time()
                }
        
        elif args.action == 'scan-file':
            if not args.file:
                result = {'success': False, 'message': 'File path required for scan-file action'}
            else:
                result = antivirus.scan_file(args.file)
        
        elif args.action == 'scan-folders':
            if not args.folders:
                result = {'success': False, 'message': 'Folder paths required for scan-folders action'}
            else:
                result = antivirus.scan_selected_folders(args.folders)
        
        elif args.action == 'scan-url':
            if not args.url:
                result = {'success': False, 'message': 'URL required for scan-url action'}
            else:
                result = antivirus.scan_url(args.url)
        
        elif args.action == 'scan-domain':
            if not args.domain:
                result = {'success': False, 'message': 'Domain required for scan-domain action'}
            else:
                result = antivirus.scan_domain(args.domain)
        
        elif args.action == 'scan-ip':
            if not args.ip:
                result = {'success': False, 'message': 'IP address required for scan-ip action'}
            else:
                result = antivirus.scan_ip_address(args.ip)
        
        elif args.action == 'status':
            result = antivirus.get_status()
        
        elif args.action == 'stats':
            result = antivirus.get_stats()
        
        elif args.action == 'update-db':
            result = antivirus.update_database()
        
        elif args.action == 'clear-url-cache':
            result = antivirus.clear_url_cache()
        
        # Output result as JSON
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        error_result = {
            'success': False,
            'message': f'Error: {e}',
            'timestamp': time.time()
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)

if __name__ == '__main__':
    main()
