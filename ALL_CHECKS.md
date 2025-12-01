# Запуск всех проверок Semgrep

## 🎯 Запуск всех проверок

Для запуска **ВСЕХ проверок сразу** используйте:

```bash
semgrep --config=.semgrep.yml --config=semgrep-rules/airflow/ --config=semgrep-rules/airflow-strict/ dags/
```

Или для конкретного файла:

```bash
semgrep --config=.semgrep.yml --config=semgrep-rules/airflow/ --config=semgrep-rules/airflow-strict/ dags/vulnerable_dag_rce.py
```

## 📋 Что включает "все проверки"

Скрипт `run_all_checks.sh` запускает:

1. ✅ **Стандартные правила Semgrep:**
   - `p/security-audit` - общий security-аудит
   - `p/secrets` - поиск секретов

2. ✅ **Базовые кастомные правила:**
   - `semgrep-rules/airflow/airflow-bash-unsafe.yml`
   - `semgrep-rules/airflow/airflow-sql-injection.yml`
   - `semgrep-rules/airflow/airflow-rce-eval-exec.yml`
   - `semgrep-rules/airflow/airflow-secrets.yml`
   - `semgrep-rules/airflow/airflow-k8s-operator.yml`
   - `semgrep-rules/airflow/airflow-xcom-pickle.yml`

3. ✅ **Усиленные кастомные правила:**
   - `semgrep-rules/airflow-strict/airflow-rce-strict.yml`
   - `semgrep-rules/airflow-strict/airflow-sql-injection-strict.yml`
   - `semgrep-rules/airflow-strict/airflow-secrets-strict.yml`
   - `semgrep-rules/airflow-strict/airflow-bash-whitelist.yml`
   - `semgrep-rules/airflow-strict/airflow-k8s-strict.yml`

**Итого:** ~158 правил, которые проверяют все типы уязвимостей в Airflow DAG файлах.

## 🚀 Использование

### Вариант 1: Скрипт (рекомендуется)

```bash
# Все файлы в dags/
./run_all_checks.sh

# Конкретный файл
./run_all_checks.sh dags/vulnerable_dag_rce.py

# Конкретная директория
./run_all_checks.sh dags/
```

### Вариант 2: Команда напрямую

```bash
semgrep \
  --config=p/security-audit \
  --config=p/secrets \
  --config=semgrep-rules/airflow/ \
  --config=semgrep-rules/airflow-strict/ \
  dags/
```

### Вариант 3: С сохранением результатов

```bash
# JSON
./run_all_checks.sh dags/ > results.json

# Или через команду
semgrep \
  --config=p/security-audit \
  --config=p/secrets \
  --config=semgrep-rules/airflow/ \
  --config=semgrep-rules/airflow-strict/ \
  dags/ \
  --json > results.json

# SARIF (для CI/CD)
semgrep \
  --config=p/security-audit \
  --config=p/secrets \
  --config=semgrep-rules/airflow/ \
  --config=semgrep-rules/airflow-strict/ \
  dags/ \
  --sarif > results.sarif
```

## 📊 Ожидаемые результаты

При запуске всех проверок на тестовых файлах:

- **Найдено проблем:** ~174 в 5 файлах
- **Правил запущено:** ~158
- **Время выполнения:** несколько секунд

### По типам уязвимостей:

1. **RCE уязвимости** - 20+ проблем
2. **SQL-инъекции** - 10+ проблем
3. **Утечки секретов** - 10+ проблем
4. **Инъекции через операторы** - 15+ проблем
5. **Стандартные правила** - дополнительные проверки

## ⚙️ Настройка

### Исключить определенные правила

Если нужно исключить некоторые правила, отредактируйте `run_all_checks.sh`:

```bash
# Комментируйте ненужные --config
semgrep \
  --config=p/security-audit \
  # --config=p/secrets  # Исключено
  --config=semgrep-rules/airflow/ \
  --config=semgrep-rules/airflow-strict/ \
  "$TARGET_DIR"
```

### Только кастомные правила (без стандартных)

```bash
semgrep \
  --config=semgrep-rules/airflow/ \
  --config=semgrep-rules/airflow-strict/ \
  dags/
```

### Только стандартные правила

```bash
semgrep \
  --config=p/security-audit \
  --config=p/secrets \
  dags/
```

## 🔍 Детальный анализ

### Просмотр конкретных типов проблем

```bash
# Только RCE
./run_all_checks.sh dags/ | grep -i "eval\|exec\|pickle"

# Только SQL
./run_all_checks.sh dags/ | grep -i "sql"

# Только секреты
./run_all_checks.sh dags/ | grep -i "secret\|password\|key"
```

### Подсчет проблем

```bash
# Общее количество
./run_all_checks.sh dags/ --json | grep -c '"check_id"'

# По severity
./run_all_checks.sh dags/ --json | jq '.results | group_by(.extra.severity) | map({severity: .[0].extra.severity, count: length})'
```

## 📝 Примечания

1. **Время выполнения:** Запуск всех правил может занять несколько секунд
2. **Предупреждения:** Могут быть предупреждения о поле 'where' - это нормально, правила все равно работают
3. **Ложные срабатывания:** Некоторые правила могут давать ложные срабатывания - настройте исключения при необходимости

## 🎯 Рекомендации

- **Для разработки:** Используйте `./run_all_checks.sh` перед коммитом
- **Для CI/CD:** Используйте команду с `--sarif` для интеграции
- **Для анализа:** Используйте `--json` для детального анализа

## 📚 См. также

- `HOW_TO_TEST.md` - пошаговая инструкция по тестированию
- `TESTING.md` - детальное описание тестов
- `README.md` - общая документация

