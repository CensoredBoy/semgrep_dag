#!/usr/bin/env python3
"""Анализ качества правил Semgrep"""
import subprocess
import json
from pathlib import Path
from collections import defaultdict

def analyze_rule(rule_file, rule_id, test_file):
    """Анализировать одно правило"""
    if not test_file.exists():
        return {"status": "no_test", "issues": ["Тестовый файл не найден"]}
    
    result = subprocess.run(
        ['semgrep', '--config', str(rule_file), str(test_file), '--json'],
        capture_output=True,
        text=True
    )
    
    try:
        data = json.loads(result.stdout)
        findings = data.get('results', [])
        
        if findings:
            return {
                "status": "works",
                "findings_count": len(findings),
                "issues": []
            }
        else:
            # Читаем тест и правило, чтобы понять почему не сработало
            with open(test_file) as f:
                test_code = f.read()
            
            with open(rule_file) as f:
                rule_code = f.read()
            
            issues = []
            
            # Проверяем паттерны
            if 'pattern-inside' in rule_code and 'PythonOperator' in rule_code:
                if 'def ' in test_code and 'PythonOperator' not in test_code:
                    issues.append("Правило требует PythonOperator, но его нет в тесте")
            
            if 'dag_run.conf' in test_code and 'dag_run.conf' not in rule_code:
                issues.append("Тест использует dag_run.conf, но правило его не ищет")
            
            if '{{' in test_code and '{{' not in rule_code:
                issues.append("Тест использует Jinja шаблоны, но правило их не ищет")
            
            return {
                "status": "not_works",
                "findings_count": 0,
                "issues": issues if issues else ["Неизвестная причина"]
            }
    except:
        return {"status": "error", "issues": ["Ошибка парсинга"]}

def main():
    base_dir = Path('/Users/jkoimni/Documents/dag')
    rules_dir = base_dir / 'semgrep-rules'
    tests_dir = base_dir / 'dags' / 'tests'
    
    results = defaultdict(list)
    
    for rule_file in sorted(rules_dir.glob('**/*.yml')):
        with open(rule_file) as f:
            content = f.read()
            rule_ids = []
            for line in content.split('\n'):
                if line.strip().startswith('- id:'):
                    rule_id = line.split('id:')[1].strip()
                    rule_ids.append(rule_id)
        
        for rule_id in rule_ids:
            test_file = tests_dir / f"test_{rule_id}.py"
            analysis = analyze_rule(rule_file, rule_id, test_file)
            results[analysis["status"]].append({
                "rule_id": rule_id,
                "issues": analysis.get("issues", [])
            })
    
    print("# Анализ качества правил Semgrep\n")
    print(f"## Статистика\n")
    print(f"- ✅ Работают: {len(results['works'])}")
    print(f"- ❌ Не работают: {len(results['not_works'])}")
    print(f"- ⚠️ Нет тестов: {len(results['no_test'])}")
    print(f"- 🔴 Ошибки: {len(results['error'])}\n")
    
    if results['not_works']:
        print("## Проблемы с правилами\n")
        for item in results['not_works'][:10]:
            print(f"### {item['rule_id']}")
            for issue in item['issues']:
                print(f"- {issue}")
            print()

if __name__ == '__main__':
    main()
