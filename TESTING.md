# Инструкция по тестированию Semgrep правил

## Быстрый тест

### 1. Тест базовых правил
```bash
semgrep --config=semgrep-rules/airflow/ dags/
```

### 2. Тест усиленных правил
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/
```

### 3. Тест стандартных правил + кастомные
```bash
semgrep --config=p/security-audit --config=p/secrets --config=semgrep-rules/airflow/ dags/
```

### 4. Тест конкретного файла
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/vulnerable_dag_rce.py
```

## Детальное тестирование

### Тест RCE уязвимостей
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-rce-strict.yml dags/vulnerable_dag_rce.py
```

Ожидаемый результат: Должны быть найдены:
- eval() - везде
- exec() - везде
- pickle.loads() - везде
- os.system() - в python_callable
- subprocess с shell=True - в python_callable

### Тест SQL-инъекций
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-sql-injection-strict.yml dags/vulnerable_dag_sqli.py
```

Ожидаемый результат: Должны быть найдены все случаи конкатенации SQL.

### Тест секретов
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-secrets-strict.yml dags/vulnerable_dag_secrets.py
```

Ожидаемый результат: Должны быть найдены все хардкоженные секреты.

### Тест BashOperator
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-bash-whitelist.yml dags/vulnerable_dag_injections.py
```

Ожидаемый результат: Должны быть найдены небезопасные Jinja шаблоны.

### Тест безопасного файла
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/safe_dag_example.py
```

Ожидаемый результат: Минимум или отсутствие ошибок.

## Сохранение результатов

### В JSON
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/ --json > results.json
```

### В SARIF (для CI/CD)
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/ --sarif > results.sarif
```

### Только ошибки (ERROR severity)
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/ --severity=ERROR
```

## Автоматизированный тест

Запустите скрипт:
```bash
./test_semgrep.sh
```

Или упрощенную версию:
```bash
# Тест всех уязвимых файлов
for file in dags/vulnerable_*.py; do
    echo "=== Тестирование $file ==="
    semgrep --config=semgrep-rules/airflow-strict/ "$file"
    echo ""
done

# Тест безопасного файла
echo "=== Тестирование безопасного файла ==="
semgrep --config=semgrep-rules/airflow-strict/ dags/safe_dag_example.py
```

## Ожидаемые результаты

### vulnerable_dag_rce.py
- ✅ Найдено: eval, exec, pickle, os.system, subprocess, BashOperator с Jinja
- Ожидается: 20+ проблем

### vulnerable_dag_sqli.py
- ✅ Найдено: SQL конкатенация, f-строки, SQL из конфига
- Ожидается: 10+ проблем

### vulnerable_dag_secrets.py
- ✅ Найдено: Хардкоженные пароли, API ключи, токены
- Ожидается: 10+ проблем

### vulnerable_dag_injections.py
- ✅ Найдено: BashOperator, SSHOperator, K8s операторы с динамическими параметрами
- Ожидается: 15+ проблем

### safe_dag_example.py
- ✅ Найдено: Минимум или отсутствие проблем
- Ожидается: 0-2 проблемы (возможны ложные срабатывания)

## Известные проблемы

1. **Поле 'where' не поддерживается** в некоторых версиях Semgrep
   - Решение: Правила все равно работают, но некоторые проверки могут быть пропущены
   - Статус: Не критично, основные паттерны работают

2. **YAML валидация**
   - Все сообщения должны быть в кавычках
   - Проверка: `semgrep --validate --config=semgrep-rules/airflow/airflow-bash-unsafe.yml`

## Отладка

Если правила не работают:

1. Проверьте синтаксис YAML:
   ```bash
   semgrep --validate --config=semgrep-rules/airflow/airflow-bash-unsafe.yml
   ```

2. Проверьте версию Semgrep:
   ```bash
   semgrep --version
   ```
   Рекомендуется: >= 1.0.0

3. Запустите с подробным выводом:
   ```bash
   semgrep --config=semgrep-rules/airflow/ dags/ --verbose
   ```

4. Проверьте конкретное правило:
   ```bash
   semgrep --config=semgrep-rules/airflow/airflow-bash-unsafe.yml dags/vulnerable_dag_injections.py
   ```

