# IOC Intelligence Analyzer

Профессиональный инструмент для анализа показателей компрометации (IOC) через VirusTotal API. 
Автоматизирует процесс проверки IP-адресов, доменов и хэшей файлов на предмет киберугроз.

## 🚀 Возможности

- ✅ Автоматическое определение типов IOC (IP, domain, MD5, SHA-1, SHA-256)
- ✅ Проверка репутации через VirusTotal API v3
- ✅ Красивый табличный вывод результатов
- ✅ Сохранение результатов в CSV формате
- ✅ Обработка ошибок и лимитов API
- ✅ Поддержка аргументов командной строки

## 📦 Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/your-username/ioc-analyzer.git
cd ioc-analyzer
```
2. Установите зависимости:
```bash
pip install -r requirements.txt
```
3. Настройте API ключ:
```bash
cp .env.example .env
```
4. Отредактируйте файл .env и добавьте ваш VirusTotal API ключ:
```ini
VT_API_KEY=your_actual_virustotal_api_key_here
```

## 🛠 Использование

Базовый синтаксис:
```bash
python ioc_analyzer.py -f файл_с_ioc.txt
```
Примеры:
```bash
# Проверка IOC с выводом в консоль
python ioc_analyzer.py -f example_iocs.txt

# Проверка с сохранением в CSV
python ioc_analyzer.py -f example_iocs.txt -o results.csv
```

## 📁 Формат входного файла

Файл должен содержать по одному IOC на строку:
```text
8.8.8.8
google.com
44d88612fea8a8f36de82e1278abb02f
malicious-domain.com
```

## 🔧 Поддерживаемые типы IOC

- IPv4 адреса: 192.168.1.1

- Домены: example.com

- MD5 хэши: d41d8cd98f00b204e9800998ecf8427e

- SHA-1 хэши: da39a3ee5e6b4b0d3255bfef95601890afd80709

- SHA-256 хэши: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

## ⚠️ Важные примечания

- Бесплатный VirusTotal API имеет лимит: 500 запросов в день, 4 запроса в минуту

- Для работы требуется бесплатный аккаунт на VirusTotal
