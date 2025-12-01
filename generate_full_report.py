#!/usr/bin/env python3
import subprocess
import json
import os
from pathlib import Path

def get_rule_info(rule_file, rule_id):
    """Получить информацию о правиле из файла"""
    with open(rule_file) as f:
        content = f.read()
    
    # Ищем описание правила
    pattern = f'  - id: {rule_id}'
    idx = content.find(pattern)
    if idx == -1:
        return None
    
    # Ищем message
    msg_start = content.find('message: "', idx)
    if msg_start != -1:
        msg_start += len('message: "')
        msg_end = content.find('"', msg_start)
        message = content[msg_start:msg_end]
    else:
        message = "Описание не найдено"
    
    return message

def test_rule(rule_file, test_file):
    """Протестировать правило на тестовом файле"""
    if not os.path.exists(test_file):
        return None, "Тестовый файл не найден"
    
    result = subprocess.run(
        ['semgrep', '--config', rule_file, test_file, '--json'],
        capture_output=True,
        text=True
    )
    
    try:
        data = json.loads(result.stdout)
        findings = data.get('results', [])
        return findings, None
    except:
        return None, "Ошибка парсинга JSON"

def main():
    base_dir = Path('/Users/jkoimni/Documents/dag')
    rules_dir = base_dir / 'semgrep-rules'
    tests_dir = base_dir / 'dags' / 'tests'
    
    report = []
    report.append("# Полный отчет о тестировании кастомных правил Semgrep\n")
    report.append("## Обзор\n")
    report.append("Проверка всех кастомных правил на тестовых файлах DAG.\n")
    report.append("Для каждого правила указано:\n")
    report.append("- Описание правила\n")
    report.append("- Тестовый файл\n")
    report.append("- Результат проверки\n")
    report.append("- Объяснение, почему правило сработало или не сработало\n")
    report.append("\n---\n")
    
    # Обрабатываем все файлы правил
    for rule_file in sorted(rules_dir.glob('**/*.yml')):
        rule_name = rule_file.stem
        report.append(f"\n## Файл правил: `{rule_name}`\n")
        
        # Получаем все ID правил
        with open(rule_file) as f:
            content = f.read()
            rule_ids = []
            for line in content.split('\n'):
                if line.strip().startswith('- id:'):
                    rule_id = line.split('id:')[1].strip()
                    rule_ids.append(rule_id)
        
        for rule_id in rule_ids:
            report.append(f"\n### Правило: `{rule_id}`\n")
            
            # Получаем описание
            message = get_rule_info(rule_file, rule_id)
            if message:
                report.append(f"**Описание:** {message}\n")
            
            # Ищем тестовый файл
            test_file = tests_dir / f"test_{rule_id}.py"
            
            if test_file.exists():
                report.append(f"**Тестовый файл:** `{test_file.name}`\n")
                
                # Тестируем правило
                findings, error = test_rule(str(rule_file), str(test_file))
                
                if error:
                    report.append(f"**Ошибка:** {error}\n")
                elif findings:
                    report.append(f"**✅ Сработало:** Найдено {len(findings)} срабатывание(й)\n")
                    for finding in findings[:3]:
                        line = finding.get('start', {}).get('line', '?')
                        msg = finding.get('message', '')
                        report.append(f"- Строка {line}: {msg}\n")
                    
                    # Показываем код из теста
                    with open(test_file) as f:
                        test_lines = f.readlines()
                        for i, line in enumerate(test_lines, 1):
                            if 'ОПАСНО' in line:
                                start = max(0, i-2)
                                end = min(len(test_lines), i+2)
                                report.append(f"\n**Код в тесте (строки {start+1}-{end}):**\n")
                                report.append("```python\n")
                                report.append(''.join(test_lines[start:end]))
                                report.append("```\n")
                                break
                    
                    # Объяснение
                    report.append(f"\n**Почему сработало:**\n")
                    if 'hardcoded' in rule_id or 'secret' in rule_id:
                        report.append("Правило обнаружило хардкоженный секрет (пароль/API ключ/JWT токен) в коде. ")
                        report.append("Секрет соответствует регулярному выражению в правиле (содержит ключевые слова типа 'password', 'api_key', 'secret', 'token' и имеет достаточную длину). ")
                        report.append("Хардкоженные секреты в коде - это критическая уязвимость безопасности.\n")
                    elif 'eval' in rule_id or 'exec' in rule_id:
                        report.append("Правило обнаружило использование eval()/exec() в коде. ")
                        report.append("Это критическая уязвимость Remote Code Execution (RCE), так как позволяет выполнить произвольный Python код. ")
                        report.append("Если данные для eval/exec приходят из внешних источников (dag_run.conf, params, xcom), злоумышленник может выполнить любой код.\n")
                    elif 'pickle' in rule_id or 'marshal' in rule_id:
                        report.append("Правило обнаружило использование pickle.loads()/marshal.loads(). ")
                        report.append("Десериализация недоверенных данных может привести к RCE, так как pickle/marshal могут выполнить произвольный код при десериализации.\n")
                    elif 'bash' in rule_id:
                        report.append("Правило обнаружило использование небезопасных Jinja шаблонов в BashOperator. ")
                        report.append("Команда формируется из пользовательских данных (dag_run.conf/params/xcom), что может привести к Command Injection. ")
                        report.append("Злоумышленник может передать через HTTP запрос команду, которая будет выполнена на сервере.\n")
                    elif 'sql' in rule_id:
                        report.append("Правило обнаружило SQL Injection уязвимость. ")
                        report.append("SQL запрос формируется через конкатенацию/интерполяцию строк с пользовательскими данными вместо параметризованных запросов. ")
                        report.append("Это позволяет злоумышленнику модифицировать SQL запрос и получить несанкционированный доступ к данным.\n")
                    elif 'k8s' in rule_id or 'docker' in rule_id:
                        report.append("Правило обнаружило использование недоверенных данных для конфигурации контейнеров. ")
                        report.append("Образы, переменные окружения, volumes и другие параметры формируются из пользовательских данных, что может привести к компрометации кластера.\n")
                    elif 'xcom' in rule_id:
                        report.append("Правило обнаружило небезопасную настройку XCom. ")
                        report.append("Включение pickle для XCom позволяет передавать и выполнять произвольные Python объекты, что может привести к RCE.\n")
                    else:
                        report.append("Правило обнаружило уязвимость согласно заданным паттернам в коде.\n")
                else:
                    report.append("**❌ Не сработало**\n")
                    report.append("\nПравило не обнаружило уязвимость в тестовом файле. ")
                    report.append("Возможные причины:\n")
                    report.append("- Паттерн правила не соответствует структуре кода в тесте\n")
                    report.append("- Требуется уточнение паттерна для более точного сопоставления\n")
                    report.append("- Код в тесте может быть безопасным вариантом использования\n")
            else:
                report.append(f"**⚠️ Тестовый файл не найден:** `test_{rule_id}.py`\n")
            
            report.append("\n---\n")
    
    # Сохраняем отчет
    output_file = base_dir / 'RULE_TESTING_REPORT.md'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(''.join(report))
    
    print(f"Отчет сохранен в {output_file}")

if __name__ == '__main__':
    main()
