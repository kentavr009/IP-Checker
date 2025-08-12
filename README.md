<!-- Anchor for language switcher -->
<a name="english"></a>

# IP Reputation Checker

[Русская версия](#russian)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-brightgreen.svg)](https://www.python.org/)

A command-line tool for mass checking the reputation of IP addresses using multiple data sources. Designed for anti-fraud, traffic analysis, and security assessment tasks.

## Features

-   **Multiple Input Formats**: Check single IPs, lists from a file, or entire CIDR ranges.
-   **Rich Data Sources**:
    -   **ipwho.is**: Geo-location, ASN/ORG, and security flags (VPN, Proxy, Tor, Hosting).
    -   **ip-api.com**: Alternative geo-location, ISP/ORG data, and proxy/hosting flags.
    -   **AbuseIPDB (Optional)**: retrieves abuse confidence score and report history (requires a free API key).
-   **Advanced Heuristics**: Detects suspicious IPs based on hosting provider keywords (AWS, Google Cloud, OVH, etc.) and geo-mismatches between sources.
-   **High Performance**: Utilizes multithreading with configurable throttling and retry logic with exponential backoff.
-   **Flexible Output**: Provides a clean summary in the console and a detailed `CSV` report with a final `CLEAN`/`SUSPICIOUS` verdict and reasons.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your_username/ip-reputation-checker.git
    cd ip-reputation-checker
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    # On Windows, use: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration (Optional)

To use the **AbuseIPDB** checker, you need to obtain a free API key from their [website](https://www.abuseipdb.com/account/api) and set it as an environment variable.

```bash
# On Linux or macOS
export ABUSEIPDB_KEY="your_api_key_here"

# On Windows (Command Prompt)
set ABUSEIPDB_KEY="your_api_key_here"
```

The script will automatically detect and use the key. If the `ABUSEIPDB_KEY` is not set, this check will be skipped.

## Usage

### Quick Start

First, generate an example `ips.txt` file:
```bash
python ip_mass_check.py --init
```
This will create `ips.txt` with sample data. Now you can run the check:
```bash
python ip_mass_check.py --input ips.txt --csv report.csv
```

### Command-Line Examples

-   **Check IPs directly from arguments (including a CIDR range):**
    ```bash
    python ip_mass_check.py 8.8.8.8 1.1.1.1 203.0.113.0/30 --csv report.csv
    ```

-   **Check IPs from a file with custom threading and throttling:**
    ```bash
    python ip_mass_check.py --input ips.txt --threads 20 --sleep-min 0.2 --sleep-max 0.4
    ```

-   **Disable AbuseIPDB check even if the key is present:**
    ```bash
    python ip_mass_check.py --input ips.txt --no-abuse
    ```

## Output Example

The script prints a summary table to the console and saves a detailed report to a `.csv` file.

**Console Output:**
```
IP          | Country | City      | ORG                       | ASN          | Verdict
------------+---------+-----------+---------------------------+--------------+----------
8.8.8.8     | US      | Mountain View | Google LLC                | AS15169      | CLEAN
1.1.1.1     | US      |           | Cloudflare, Inc.          | AS13335      | CLEAN
...
```

**CSV Report (`report.csv`):**
The CSV contains detailed columns like `IP`, `Country`, `Region`, `City`, `ORG`, `ISP`, `ASN`, individual flags from each service (`ipwho_proxy`, `ipapi_hosting`), AbuseIPDB scores, and a final `Verdict` with detailed `Flags`.

---

<!-- Anchor for language switcher -->
<a name="russian"></a>

# IP Reputation Checker (Массовая проверка IP)

[English version](#english)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-brightgreen.svg)](https://www.python.org/)

Консольный инструмент для массовой проверки репутации IP-адресов с использованием нескольких источников данных. Предназначен для задач антифрода, анализа трафика и оценки безопасности.

## Возможности

-   **Разные форматы ввода**: Проверка отдельных IP, списков из файла или целых диапазонов CIDR.
-   **Источники данных**:
    -   **ipwho.is**: Геолокация, ASN/ORG и флаги безопасности (VPN, Proxy, Tor, Hosting).
    -   **ip-api.com**: Альтернативная геолокация, данные о провайдере/организации и флаги proxy/hosting.
    -   **AbuseIPDB (Опционально)**: Получение "оценки доверия" и истории жалоб (требуется бесплатный API-ключ).
-   **Продвинутые эвристики**: Обнаружение подозрительных IP на основе ключевых слов хостинг-провайдеров (AWS, Google Cloud, OVH и др.) и расхождений в геолокации между источниками.
-   **Высокая производительность**: Использует многопоточность с настраиваемым троттлингом и логикой повторных запросов с экспоненциальной задержкой.
-   **Гибкий вывод**: Отображает краткую сводку в консоли и создает подробный `CSV`-отчет с финальным вердиктом `CLEAN`/`SUSPICIOUS` и причинами.

## Установка

1.  **Клонируйте репозиторий:**
    ```bash
    git clone https://github.com/your_username/ip-reputation-checker.git
    cd ip-reputation-checker
    ```

2.  **Создайте виртуальное окружение (рекомендуется):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    # В Windows используйте: venv\Scripts\activate
    ```

3.  **Установите зависимости:**
    ```bash
    pip install -r requirements.txt
    ```

## Конфигурация (Опционально)

Для использования проверки через **AbuseIPDB** необходимо получить бесплатный API-ключ на их [сайте](https://www.abuseipdb.com/account/api) и установить его как переменную окружения.

```bash
# В Linux или macOS
export ABUSEIPDB_KEY="ваш_api_ключ"

# В Windows (Command Prompt)
set ABUSEIPDB_KEY="ваш_api_ключ"
```
Скрипт автоматически обнаружит и использует ключ. Если переменная `ABUSEIPDB_KEY` не установлена, эта проверка будет пропущена.

## Использование

### Быстрый старт

Сначала сгенерируйте файл с примерами `ips.txt`:
```bash
python ip_mass_check.py --init
```
Это создаст `ips.txt` с примерами. Теперь можно запустить проверку:
```bash
python ip_mass_check.py --input ips.txt --csv report.csv
```

### Примеры команд

-   **Проверить IP напрямую из аргументов (включая CIDR-диапазон):**
    ```bash
    python ip_mass_check.py 8.8.8.8 1.1.1.1 203.0.113.0/30 --csv report.csv
    ```

-   **Проверить IP из файла с настройкой потоков и задержек:**
    ```bash
    python ip_mass_check.py --input ips.txt --threads 20 --sleep-min 0.2 --sleep-max 0.4
    ```

-   **Отключить проверку AbuseIPDB, даже если ключ задан:**
    ```bash
    python ip_mass_check.py --input ips.txt --no-abuse
    ```

## Пример вывода

Скрипт выводит итоговую таблицу в консоль и сохраняет детальный отчет в `.csv` файл.

**Вывод в консоль:**
```
IP          | Country | City      | ORG                       | ASN          | Verdict
------------+---------+-----------+---------------------------+--------------+----------
8.8.8.8     | US      | Mountain View | Google LLC                | AS15169      | CLEAN
1.1.1.1     | US      |           | Cloudflare, Inc.          | AS13335      | CLEAN
...
```

**CSV-отчет (`report.csv`):**
CSV-файл содержит подробные колонки: `IP`, `Country`, `Region`, `City`, `ORG`, `ISP`, `ASN`, отдельные флаги от каждого сервиса (`ipwho_proxy`, `ipapi_hosting`), оценки AbuseIPDB, а также финальный `Verdict` с детальным списком причин `Flags`.
