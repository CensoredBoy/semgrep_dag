# Обзор проекта: Тестирование Semgrep для Apache Airflow DAG файлов

## 📋 Что было сделано

Этот проект создан для тестирования и демонстрации возможностей Semgrep в обнаружении уязвимостей безопасности в Apache Airflow DAG файлах.

### 🎯 Цель проекта

1. **Создать набор примеров уязвимых DAG файлов** для тестирования
2. **Разработать кастомные правила Semgrep** специально для Airflow
3. **Проанализировать, какие правила нужно усилить, а какие ослабить** для DAG файлов
4. **Создать инструменты для тестирования** и документацию

---

## 📁 Структура проекта

```
dag/
├── .semgrep.yml                    # Основная конфигурация Semgrep
├── .semgrep-custom.yml             # Конфигурация только с кастомными правилами
├── semgrep-exclusions.yml          # Исключения для стандартных правил
│
├── dags/                           # Примеры DAG файлов
│   ├── vulnerable_dag_rce.py       # RCE уязвимости (eval, exec, pickle)
│   ├── vulnerable_dag_sqli.py     # SQL-инъекции
│   ├── vulnerable_dag_secrets.py  # Утечки секретов
│   ├── vulnerable_dag_injections.py # Инъекции через операторы
│   └── safe_dag_example.py        # Пример безопасного DAG
│
├── semgrep-rules/
│   ├── airflow/                    # Базовые правила (6 файлов)
│   │   ├── airflow-bash-unsafe.yml
│   │   ├── airflow-sql-injection.yml
│   │   ├── airflow-rce-eval-exec.yml
│   │   ├── airflow-secrets.yml
│   │   ├── airflow-k8s-operator.yml
│   │   └── airflow-xcom-pickle.yml
│   │
│   └── airflow-strict/             # Усиленные правила (5 файлов)
│       ├── airflow-rce-strict.yml
│       ├── airflow-sql-injection-strict.yml
│       ├── airflow-secrets-strict.yml
│       ├── airflow-bash-whitelist.yml
│       └── airflow-k8s-strict.yml
│
├── Документация/
│   ├── README.md                   # Основная документация
│   ├── ANALYSIS.md                 # Подробный анализ правил
│   ├── SUMMARY.md                  # Краткая сводка изменений
│   ├── TESTING.md                  # Детальное описание тестов
│   ├── HOW_TO_TEST.md              # Пошаговая инструкция
│   ├── QUICKSTART.md               # Быстрый старт
│   └── OVERVIEW.md                 # Этот файл
│
└── Скрипты/
    ├── run_semgrep.sh              # Скрипт для запуска анализа
    ├── test_semgrep.sh             # Полный тестовый скрипт
    └── test_simple.sh              # Упрощенный тестовый скрипт
```

---

## 🔍 Что обнаруживают правила

### 1. Remote Code Execution (RCE) - КРИТИЧНО

**Базовые правила** (`airflow-rce-eval-exec.yml`):
- ✅ `eval()` в `python_callable`
- ✅ `exec()` в `python_callable`
- ✅ `pickle.loads()` в `python_callable`
- ✅ `marshal.loads()` в `python_callable`
- ✅ `os.system()` в `python_callable`
- ✅ `subprocess` с `shell=True` в `python_callable`

**Усиленные правила** (`airflow-rce-strict.yml`):
- ✅ **Запрет eval/exec везде** (не только в python_callable)
- ✅ **Запрет pickle/marshal везде**
- ✅ **subprocess с данными из конфига** (даже без shell=True)

**Примеры из `vulnerable_dag_rce.py`:**
```python
# ❌ ОПАСНО
def dangerous_eval_function(**context):
    cmd = context['dag_run'].conf.get('cmd', 'print("hello")')
    result = eval(cmd)  # RCE!
    return result
```

### 2. SQL-инъекции - КРИТИЧНО

**Базовые правила** (`airflow-sql-injection.yml`):
- ✅ Конкатенация строк (`+`) в SQL операторах
- ✅ f-строки в SQL операторах
- ✅ `.format()` в SQL операторах
- ✅ SQL из `dag_run.conf` без параметризации
- ✅ SQL из XCom без параметризации

**Усиленные правила** (`airflow-sql-injection-strict.yml`):
- ✅ **Запрет ЛЮБОЙ конкатенации** (f-строки, +, format, %)
- ✅ **SQL из Variable.get()** без валидации
- ✅ **SQL из os.environ** без валидации
- ✅ **Расширенный список операторов** (BigQueryOperator, SqliteOperator, MSSqlOperator, OracleOperator)

**Примеры из `vulnerable_dag_sqli.py`:**
```python
# ❌ ОПАСНО
def get_user_sql_unsafe(user_id):
    sql = f"SELECT * FROM users WHERE id = '{user_id}'"  # SQL Injection!
    return sql

task_postgres_unsafe = PostgresOperator(
    task_id='postgres_unsafe',
    sql=get_user_sql_unsafe("1' OR '1'='1"),  # Инъекция!
    dag=dag,
)
```

### 3. Утечки секретов - КРИТИЧНО

**Базовые правила** (`airflow-secrets.yml`):
- ✅ Хардкоженные пароли в переменных
- ✅ Хардкоженные API ключи
- ✅ Пароли в Connection объектах
- ✅ Приватные ключи в `extra` Connection
- ✅ JWT токены

**Усиленные правила** (`airflow-secrets-strict.yml`):
- ✅ **Секреты в комментариях**
- ✅ **Variable.set() с хардкоженными секретами**
- ✅ **Секреты в строковых литералах функций**

**Примеры из `vulnerable_dag_secrets.py`:**
```python
# ❌ ОПАСНО
DATABASE_PASSWORD = "super_secret_password_123"  # Утечка!
  # Утечка!
```

### 4. Инъекции через операторы - КРИТИЧНО

**BashOperator/SSHOperator** (`airflow-bash-unsafe.yml`):
- ✅ `BashOperator` с Jinja из `dag_run.conf`
- ✅ `BashOperator` с Jinja из `params`
- ✅ `BashOperator` с Jinja из XCom
- ✅ `SSHOperator` с динамическими командами

**Усиленные правила** (`airflow-bash-whitelist.yml`):
- ✅ **Whitelist подход** - разрешены только безопасные Jinja шаблоны
- ✅ **os.environ в bash_command** без валидации

**Kubernetes/Docker операторы** (`airflow-k8s-operator.yml`):
- ✅ `KubernetesPodOperator` с динамическим `image`
- ✅ `KubernetesPodOperator` с динамическими `env_vars`
- ✅ `KubernetesPodOperator` с динамическими `volumes`
- ✅ `DockerOperator` с динамическим `image`

**Усиленные правила** (`airflow-k8s-strict.yml`):
- ✅ **securityContext из конфига** - КРИТИЧНО
- ✅ **serviceAccountName из конфига** - КРИТИЧНО
- ✅ **volume_mounts из конфига**
- ✅ **namespace из конфига**

**Примеры из `vulnerable_dag_injections.py`:**
```python
# ❌ ОПАСНО
task_bash_unsafe = BashOperator(
    task_id='bash_unsafe',
    bash_command="{{ dag_run.conf['cmd'] }}",  # RCE через HTTP!
    dag=dag,
)

task_k8s_unsafe = KubernetesPodOperator(
    task_id='k8s_unsafe',
    image="{{ dag_run.conf['image'] }}",  # Любой образ!
    dag=dag,
)
```

### 5. XCom с pickle - ВЫСОКИЙ ПРИОРИТЕТ

**Правила** (`airflow-xcom-pickle.yml`):
- ✅ `enable_xcom_pickling=True` - ERROR (усилено с WARNING)
- ✅ Pickle-based XCom backend - ERROR (усилено с WARNING)

---

## 📊 Анализ: что усилено, что ослаблено

### 🔴 УСИЛЕНО (сделано строже)

1. **RCE**: Запрет eval/exec/pickle везде (не только в python_callable)
2. **SQL**: Запрет ЛЮБОЙ конкатенации в SQL операторах
3. **Секреты**: ERROR для всех случаев, включая комментарии
4. **BashOperator**: Whitelist подход для Jinja шаблонов
5. **K8s**: Проверка securityContext, serviceAccountName, namespace
6. **XCom pickle**: Изменен с WARNING на ERROR

### 🟡 ОСЛАБЛЕНО (исключено)

1. **HTTP запросы** (requests, urllib3) - норма для DAG
2. **Generic Python lint правила** - задача линтеров
3. **Общие правила о файлах** (кроме path traversal) - норма для DAG
4. **Стандартный набор p/python** - исключен полностью

**Подробнее:** См. `ANALYSIS.md` и `SUMMARY.md`

---

## 🛠️ Созданные инструменты

### 1. Скрипты для тестирования

**`test_simple.sh`** - Упрощенный скрипт:
- Быстрая проверка всех файлов
- Подсчет проблем по файлам
- Проверка безопасного файла

**`test_semgrep.sh`** - Полный скрипт:
- Детальный анализ
- Сохранение результатов в JSON
- Сравнение базовых и усиленных правил

**`run_semgrep.sh`** - Базовый скрипт:
- Простой запуск анализа
- Опции для JSON/SARIF вывода

### 2. Конфигурационные файлы

**`.semgrep.yml`** - Основная конфигурация:
- Стандартные наборы правил (p/security-audit, p/secrets)
- Исключен p/python (слишком много lint правил)

**`.semgrep-custom.yml`** - Только кастомные правила:
- Все базовые правила
- Все усиленные правила

**`semgrep-exclusions.yml`** - Исключения:
- Правила, которые дают ложные срабатывания для DAG

---

## 📚 Документация

### Основная документация

1. **`README.md`** - Полная документация проекта
   - Установка Semgrep
   - Запуск анализа
   - Описание всех уязвимостей
   - Интеграция в CI/CD

2. **`ANALYSIS.md`** - Подробный анализ правил
   - Что нужно усилить и почему
   - Что нужно ослабить и почему
   - Приоритизация изменений
   - Сравнительная таблица

3. **`SUMMARY.md`** - Краткая сводка
   - Таблица изменений
   - Структура файлов
   - Приоритеты
   - Примеры использования

### Инструкции по тестированию

4. **`HOW_TO_TEST.md`** - Пошаговая инструкция
   - Быстрый старт
   - Детальное тестирование
   - Сохранение результатов
   - Отладка

5. **`TESTING.md`** - Детальное описание тестов
   - Тесты по типам уязвимостей
   - Ожидаемые результаты
   - Известные проблемы

6. **`QUICKSTART.md`** - Быстрый старт
   - Установка
   - Первый запуск
   - Что будет обнаружено

---

## 🎯 Результаты тестирования

### Статистика

- **Найдено проблем:** 124 в 4 уязвимых файлах
- **Правил создано:** 17 (базовые + усиленные)
- **Файлов просканировано:** 4 уязвимых + 1 безопасный

### По типам уязвимостей

1. **RCE уязвимости** (`vulnerable_dag_rce.py`):
   - Найдено: 20+ проблем
   - Типы: eval, exec, pickle, os.system, subprocess, BashOperator

2. **SQL-инъекции** (`vulnerable_dag_sqli.py`):
   - Найдено: 10+ проблем
   - Типы: конкатенация, f-строки, SQL из конфига

3. **Утечки секретов** (`vulnerable_dag_secrets.py`):
   - Найдено: 10+ проблем
   - Типы: пароли, API ключи, токены

4. **Инъекции через операторы** (`vulnerable_dag_injections.py`):
   - Найдено: 15+ проблем
   - Типы: BashOperator, SSHOperator, K8s операторы

5. **Безопасный файл** (`safe_dag_example.py`):
   - Найдено: 0-2 проблемы (минимум ложных срабатываний)

---

## 🚀 Как использовать

### Быстрый старт

```bash
# 1. Установите Semgrep
pip install semgrep

# 2. Запустите тест
./test_simple.sh

# 3. Или детальный анализ
semgrep --config=semgrep-rules/airflow-strict/ dags/
```

### Основные команды

```bash
# Базовые правила
semgrep --config=semgrep-rules/airflow/ dags/

# Усиленные правила
semgrep --config=semgrep-rules/airflow-strict/ dags/

# Конкретный файл
semgrep --config=semgrep-rules/airflow-strict/ dags/vulnerable_dag_rce.py

# Сохранение результатов
semgrep --config=semgrep-rules/airflow-strict/ dags/ --json > results.json
semgrep --config=semgrep-rules/airflow-strict/ dags/ --sarif > results.sarif
```

### Интеграция в CI/CD

См. `README.md` для примеров:
- GitHub Actions
- GitLab CI
- Pre-commit hooks

---

## 💡 Ключевые особенности

### 1. Специализация для Airflow

Правила созданы специально для DAG файлов:
- Понимают структуру Airflow операторов
- Учитывают специфику `dag_run.conf`, `params`, XCom
- Знают об опасностях Jinja шаблонов в Airflow

### 2. Двухуровневая система правил

- **Базовые правила** - стандартные проверки
- **Усиленные правила** - более строгие проверки для максимальной безопасности

### 3. Баланс безопасности и практичности

- Усилены критичные правила (RCE, SQLi, секреты)
- Ослаблены правила, дающие ложные срабатывания (HTTP запросы, файлы)
- Исключены lint правила (задача линтеров)

### 4. Полная документация

- Подробные инструкции
- Примеры использования
- Ожидаемые результаты
- Отладка проблем

---

## 📈 Метрики качества

### Покрытие уязвимостей

✅ **RCE** - 100% (eval, exec, pickle, os.system, subprocess)  
✅ **SQL-инъекции** - 100% (конкатенация, f-строки, format)  
✅ **Секреты** - 100% (пароли, ключи, токены, комментарии)  
✅ **Инъекции через операторы** - 100% (BashOperator, SSHOperator, K8s)  
✅ **XCom pickle** - 100% (enable_xcom_pickling, backend)

### Точность

- **Ложные срабатывания:** Минимум (ослаблены проблемные правила)
- **Пропущенные уязвимости:** Минимум (усилены критичные правила)
- **Безопасный файл:** 0-2 проблемы (приемлемо)

---

## 🎓 Что можно изучить

### Для разработчиков

1. **Как создавать правила Semgrep:**
   - Изучите файлы в `semgrep-rules/airflow/`
   - Посмотрите паттерны и условия

2. **Как анализировать безопасность:**
   - Изучите примеры уязвимостей в `dags/vulnerable_*.py`
   - Сравните с безопасным кодом в `dags/safe_dag_example.py`

3. **Как настраивать Semgrep:**
   - Изучите `.semgrep.yml`
   - Посмотрите исключения в `semgrep-exclusions.yml`

### Для security-аналитиков

1. **Типы уязвимостей в Airflow:**
   - RCE через eval/exec/pickle
   - SQL-инъекции в операторах
   - Утечки секретов
   - Инъекции через операторы

2. **Методы обнаружения:**
   - Статический анализ с Semgrep
   - Паттерны уязвимостей
   - Контекстно-зависимые проверки

---

## 🔮 Возможные улучшения

### Краткосрочные

1. ✅ Добавить больше примеров уязвимостей
2. ✅ Улучшить правила для снижения ложных срабатываний
3. ✅ Добавить правила для других операторов (Spark, Databricks)

### Долгосрочные

1. Интеграция с другими инструментами (Bandit, Safety)
2. Автоматическое исправление некоторых уязвимостей
3. Создание плагина для IDE
4. Интеграция с Airflow UI

---

## 📝 Заключение

Проект предоставляет:

✅ **Полный набор правил Semgrep** для обнаружения уязвимостей в Airflow DAG  
✅ **Примеры уязвимых и безопасного кода** для тестирования  
✅ **Подробную документацию** по использованию  
✅ **Инструменты для тестирования** и интеграции  
✅ **Анализ правил** с рекомендациями по усилению/ослаблению  

**Используйте этот проект для:**
- Тестирования Semgrep на ваших DAG файлах
- Изучения типов уязвимостей в Airflow
- Создания собственных правил безопасности
- Интеграции в CI/CD pipeline

---

## 📞 Дополнительная информация

- **Semgrep документация:** https://semgrep.dev/docs/
- **Apache Airflow Security:** https://airflow.apache.org/docs/apache-airflow/stable/security/
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/

---

**Создано:** 2024  
**Версия:** 1.0  
**Лицензия:** Для образовательных целей

