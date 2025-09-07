import argparse
import os
import re
import csv
from dotenv import load_dotenv
import requests
from tabulate import tabulate
import time
import json

load_dotenv()

VT_API_KEY = os.getenv('VT_API_KEY')
# Base URL для VirusTotal API v3
VT_API_URL = 'https://www.virustotal.com/api/v3'

def classify_ioc(ioc):
    ioc = ioc.strip().lower()
    
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    md5_pattern = r'^[a-f0-9]{32}$'
    sha1_pattern = r'^[a-f0-9]{40}$'
    sha256_pattern = r'^[a-f0-9]{64}$'
    
    if re.match(ipv4_pattern, ioc):
        octets = ioc.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return 'ipv4'
    elif re.match(md5_pattern, ioc):
        return 'md5'
    elif re.match(sha1_pattern, ioc):
        return 'sha1'
    elif re.match(sha256_pattern, ioc):
        return 'sha256'
    elif re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', ioc):
        return 'domain'
    
    return 'unknown'

def make_vt_request(url_suffix):
    url = f'{VT_API_URL}/{url_suffix}'
    headers = {'x-apikey': VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        if 'x-ratelimit-remaining' in response.headers:
            remaining = int(response.headers['x-ratelimit-remaining'])
            if remaining < 2:
                print(f"Внимание: Осталось {remaining} запросов в минуту")
        
        return response.json()
    
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса к VirusTotal: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Ошибка парсинга JSON: {e}")
        return None

def check_ioc_virustotal(ioc, ioc_type):
    endpoints = {
        'ipv4': f'ip_addresses/{ioc}',
        'domain': f'domains/{ioc}',
        'md5': f'files/{ioc}',
        'sha1': f'files/{ioc}',
        'sha256': f'files/{ioc}'
    }
    
    if ioc_type not in endpoints:
        return None
    
    result = make_vt_request(endpoints[ioc_type])
    if not result:
        return None
    
    data = result.get('data', {})
    attributes = data.get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    return {
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'undetected': stats.get('undetected', 0),
        'harmless': stats.get('harmless', 0),
        'total_engines': sum(stats.values()),
        'reputation': attributes.get('reputation', 0),
        'last_analysis_date': attributes.get('last_analysis_date', 'N/A')
    }

def read_iocs_from_file(file_path):
    iocs = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    iocs.append(line)
        return iocs
    except FileNotFoundError:
        print(f"Ошибка: Файл {file_path} не найден")
        return []
    except Exception as e:
        print(f"Ошибка чтения файла: {e}")
        return []

def save_to_csv(results, filename):
    if not results:
        print("Нет данных для сохранения в CSV")
        return False
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['IOC', 'Type', 'Malicious', 'Suspicious', 'Total Engines', 'Reputation', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        
        print(f"✓ Результаты сохранены в файл: {filename}")
        return True
        
    except Exception as e:
        print(f"❌ Ошибка при сохранении в CSV: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='IOC Intelligence Analyzer - Проверка показателей компрометации через VirusTotal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Примеры использования:
  python ioc_analyzer.py -f iocs.txt
  python ioc_analyzer.py --file samples/malicious_iocs.txt -o results.csv'''
    )
    parser.add_argument('-f', '--file', required=True, 
                       help='Путь к файлу с IOC (по одному на строку)')
    parser.add_argument('-o', '--output', 
                       help='Сохранить результаты в CSV файл')
    
    args = parser.parse_args()
    
    if not VT_API_KEY:
        print("Ошибка: Не найден VirusTotal API ключ.")
        print("Создайте файл .env с переменной VT_API_KEY=your_api_key")
        return
    
    iocs = read_iocs_from_file(args.file)
    if not iocs:
        print("Не найдено IOC для анализа")
        return
    
    print(f"Найдено {len(iocs)} IOC для анализа...\n")
    
    results = []
    unknown_iocs = []
    
    for i, ioc in enumerate(iocs, 1):
        ioc_type = classify_ioc(ioc)
        
        if ioc_type == 'unknown':
            unknown_iocs.append(ioc)
            continue
        
        print(f"Обрабатывается {i}/{len(iocs)}: {ioc} ({ioc_type})")
        
        vt_result = check_ioc_virustotal(ioc, ioc_type)
        
        if vt_result:
            status = "CLEAN"
            if vt_result['malicious'] > 5:
                status = "MALICIOUS"
            elif vt_result['malicious'] > 0:
                status = "SUSPICIOUS"
            
            results.append({
                'IOC': ioc,
                'Type': ioc_type,
                'Malicious': vt_result['malicious'],
                'Suspicious': vt_result['suspicious'],
                'Total Engines': vt_result['total_engines'],
                'Reputation': vt_result['reputation'],
                'Status': status
            })
        else:
            results.append({
                'IOC': ioc,
                'Type': ioc_type,
                'Malicious': 'ERROR',
                'Suspicious': 'ERROR',
                'Total Engines': 'ERROR',
                'Reputation': 'ERROR',
                'Status': 'API ERROR'
            })
        
        time.sleep(15)
    
    if results:
        print("\n" + "="*80)
        print("РЕЗУЛЬТАТЫ АНАЛИЗА IOC")
        print("="*80)
        
        table_data = []
        for result in results:
            table_data.append([
                result['IOC'],
                result['Type'],
                result['Malicious'],
                result['Suspicious'],
                result['Total Engines'],
                result['Reputation'],
                result['Status']
            ])
        
        headers = ['IOC', 'Type', 'Malicious', 'Suspicious', 'Total Engines', 'Reputation', 'Status']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        
        if args.output:
            save_to_csv(results, args.output)
        
        malicious_count = sum(1 for r in results if r['Status'] in ['MALICIOUS', 'SUSPICIOUS'])
        clean_count = len(results) - malicious_count
        
        print(f"\nСТАТИСТИКА:")
        print(f"Всего обработано IOC: {len(results)}")
        print(f"Найдено потенциально опасных: {malicious_count}")
        print(f"Чистых: {clean_count}")
    
    if unknown_iocs:
        print(f"\nНераспознанные IOC ({len(unknown_iocs)}):")
        for ioc in unknown_iocs:
            print(f"  - {ioc}")

if __name__ == "__main__":

    main()
