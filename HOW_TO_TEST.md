# Как протестировать Semgrep правила

## 🚀 Быстрый старт

### Вариант 1: Простой тест (рекомендуется)
```bash
./test_simple.sh
```

### Вариант 2: Ручной тест
```bash
# Тест усиленных правил на всех файлах
semgrep --config=semgrep-rules/airflow-strict/ dags/

# Тест конкретного файла
semgrep --config=semgrep-rules/airflow-strict/ dags/vulnerable_dag_rce.py
```

## 📋 Пошаговое тестирование

### Шаг 1: Проверка установки
```bash
semgrep --version
# Должно показать версию (например, 1.144.0)
```

### Шаг 2: Тест базовых правил
```bash
semgrep --config=semgrep-rules/airflow/ dags/
```

**Ожидаемый результат:** Найдены проблемы в уязвимых файлах

### Шаг 3: Тест усиленных правил
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/
```

**Ожидаемый результат:** Найдено больше проблем (более строгие правила)

### Шаг 4: Тест конкретных уязвимостей

#### RCE уязвимости
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-rce-strict.yml dags/vulnerable_dag_rce.py
```

Должны быть найдены:
- ✅ `eval()` - везде в файле
- ✅ `exec()` - везде в файле  
- ✅ `pickle.loads()` - везде в файле
- ✅ `os.system()` - в python_callable
- ✅ `subprocess` с shell=True - в python_callable

#### SQL-инъекции
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-sql-injection-strict.yml dags/vulnerable_dag_sqli.py
```

Должны быть найдены все случаи конкатенации SQL.

#### Секреты
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-secrets-strict.yml dags/vulnerable_dag_secrets.py
```

Должны быть найдены все хардкоженные секреты.

#### BashOperator
```bash
semgrep --config=semgrep-rules/airflow-strict/airflow-bash-whitelist.yml dags/vulnerable_dag_injections.py
```

Должны быть найдены небезопасные Jinja шаблоны.

### Шаг 5: Проверка безопасного файла
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/safe_dag_example.py
```

**Ожидаемый результат:** Минимум или отсутствие проблем

## 📊 Сохранение результатов

### В JSON формате
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/ --json > results.json
```

### В SARIF формате (для CI/CD)
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/ --sarif > results.sarif
```

### Только ошибки (ERROR severity)
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/ --severity=ERROR
```

## 🔍 Детальный анализ

### Подсчет найденных проблем
```bash
# Общее количество
semgrep --config=semgrep-rules/airflow-strict/ dags/ --json | grep -c '"check_id"'

# По файлам
for file in dags/vulnerable_*.py; do
    echo "$(basename $file): $(semgrep --config=semgrep-rules/airflow-strict/ "$file" --json | grep -c '"check_id"') проблем"
done
```

### Просмотр конкретных правил
```bash
# Показать только RCE проблемы
semgrep --config=semgrep-rules/airflow-strict/airflow-rce-strict.yml dags/vulnerable_dag_rce.py

# Показать только SQL проблемы
semgrep --config=semgrep-rules/airflow-strict/airflow-sql-injection-strict.yml dags/vulnerable_dag_sqli.py
```

## ✅ Ожидаемые результаты

### vulnerable_dag_rce.py
- **Ожидается:** 20+ проблем
- **Типы:** eval, exec, pickle, os.system, subprocess, BashOperator с Jinja

### vulnerable_dag_sqli.py
- **Ожидается:** 10+ проблем
- **Типы:** SQL конкатенация, f-строки, SQL из конфига

### vulnerable_dag_secrets.py
- **Ожидается:** 10+ проблем
- **Типы:** Хардкоженные пароли, API ключи, токены

### vulnerable_dag_injections.py
- **Ожидается:** 15+ проблем
- **Типы:** BashOperator, SSHOperator, K8s операторы с динамическими параметрами

### safe_dag_example.py
- **Ожидается:** 0-2 проблемы (возможны ложные срабатывания)
- **Типы:** Минимум или отсутствие проблем

## 🐛 Отладка

### Если правила не работают:

1. **Проверьте синтаксис YAML:**
   ```bash
   semgrep --validate --config=semgrep-rules/airflow/airflow-bash-unsafe.yml
   ```

2. **Проверьте версию Semgrep:**
   ```bash
   semgrep --version
   ```
   Рекомендуется: >= 1.0.0

3. **Запустите с подробным выводом:**
   ```bash
   semgrep --config=semgrep-rules/airflow/ dags/ --verbose
   ```

4. **Проверьте конкретное правило:**
   ```bash
   semgrep --config=semgrep-rules/airflow/airflow-bash-unsafe.yml dags/vulnerable_dag_injections.py
   ```

## 📝 Примеры вывода

### Успешный тест
```
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 42 (42 blocking)
 • Rules run: 17
 • Targets scanned: 1
```

### Найденные проблемы
```
dags/vulnerable_dag_rce.py
   ❯❯❱ airflow-eval-anywhere
          КРИТИЧНО: Использование eval() запрещено в DAG файлах.
          
           28┆ result = eval(cmd)  # ОПАСНО!
```

## 🎯 Следующие шаги

После тестирования:
1. Просмотрите найденные проблемы
2. Убедитесь, что все уязвимости обнаружены
3. Проверьте безопасный файл (не должно быть ложных срабатываний)
4. Настройте исключения при необходимости
5. Интегрируйте в CI/CD (см. README.md)

## 📚 Дополнительная информация

- **Подробная документация:** `TESTING.md`
- **Анализ правил:** `ANALYSIS.md`
- **Краткая сводка:** `SUMMARY.md`
- **Основной README:** `README.md`

