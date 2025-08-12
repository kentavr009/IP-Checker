#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Запускает профили Octo Browser по их UUID, подключается через Selenium
и проверяет IP-адрес каждого профиля.
"""
import os
import sys
import argparse
import requests
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- КОНФИГУРАЦИЯ ---
load_dotenv()
PORT = os.getenv("OCTO_LOCAL_PORT", "58888")
API_TOKEN = os.getenv("OCTO_API_TOKEN")
BASE_URL = f"http://127.0.0.1:{PORT}"
HEADERS = {"X-Octo-Api-Token": API_TOKEN, "Content-Type": "application/json"}
REQ_TIMEOUT = 15  # Таймаут для API запросов в секундах

def start_profile(uid: str) -> int:
    """Запускает профиль через Local API и возвращает debug-порт."""
    url = f"{BASE_URL}/api/profiles/start"
    payload = {"uuid": uid, "headless": False, "debug_port": True}
    
    print(f"▶️  Профиль {uid}: запуск...")
    resp = requests.post(url, json=payload, headers=HEADERS, timeout=REQ_TIMEOUT)
    
    if resp.status_code == 400:
        print(f"⛔️ [400 Bad Request] Проверьте, что профиль не запущен. Ответ API: {resp.text}")
    resp.raise_for_status() # Вызовет исключение для других HTTP-ошибок
    
    debug_port = resp.json().get("debug_port")
    if not debug_port:
        raise ValueError("API не вернул debug_port")
        
    print(f"✅ Профиль {uid}: запущен на порту {debug_port}")
    return debug_port

def attach_to_profile(port: int) -> webdriver.Chrome:
    """Подключается к запущенному профилю Chrome через Selenium."""
    opts = Options()
    opts.add_experimental_option("debuggerAddress", f"127.0.0.1:{port}")
    # Убедитесь, что chromedriver находится в системном PATH или укажите путь:
    # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
    return webdriver.Chrome(options=opts)

def check_ip(driver: webdriver.Chrome) -> str:
    """Переходит на сайт и получает IP-адрес."""
    driver.get("https://httpbin.org/ip")
    # Ожидаем появления элемента <pre> на странице
    pre_element = WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.TAG_NAME, "pre"))
    )
    # Извлекаем IP-адрес из JSON-ответа
    ip_data = pre_element.text
    return ip_data.strip()

def main(uids: list[str]):
    """Главная функция для итерации по списку UUID профилей."""
    for uid in uids:
        driver = None
        try:
            debug_port = start_profile(uid)
            driver = attach_to_profile(debug_port)
            
            ip_address = check_ip(driver)
            print(f"   IP-адрес: {ip_address}\n")
            
        except requests.RequestException as e:
            print(f"⛔️ Ошибка API для профиля {uid}: {e}\n")
        except Exception as e:
            print(f"⛔️ Непредвиденная ошибка для профиля {uid}: {e}\n")
        finally:
            if driver:
                driver.quit()

if __name__ == "__main__":
    if not API_TOKEN:
        sys.exit("⛔️ OCTO_API_TOKEN не задан в .env файле. Пожалуйста, настройте его.")
        
    parser = argparse.ArgumentParser(
        description="Запускает профили Octo Browser и проверяет их IP."
    )
    parser.add_argument(
        'profile_uids', 
        nargs='+', 
        metavar='UUID', 
        help='Один или несколько UUID профилей для запуска'
    )
    args = parser.parse_args()
    
    main(args.profile_uids)
