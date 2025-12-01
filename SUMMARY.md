# Краткая сводка: Усиление и ослабление правил Semgrep для DAG

## 🔴 УСИЛЕНЫ (сделаны строже)

### 1. RCE (Remote Code Execution)
- ✅ **Запрет eval/exec везде** (не только в python_callable)
- ✅ **Запрет pickle/marshal везде** (не только в python_callable)
- ✅ **subprocess с данными из конфига** (даже без shell=True)

**Файлы:** `semgrep-rules/airflow-strict/airflow-rce-strict.yml`

### 2. SQL-инъекции
- ✅ **Запрет ЛЮБОЙ конкатенации** в SQL операторах (f-строки, +, format, %)
- ✅ **SQL из Variable.get()** без валидации
- ✅ **SQL из os.environ** без валидации
- ✅ **Расширенный список операторов** (BigQueryOperator, SqliteOperator, MSSqlOperator, OracleOperator)

**Файлы:** `semgrep-rules/airflow-strict/airflow-sql-injection-strict.yml`

### 3. Секреты
- ✅ **Секреты в комментариях**
- ✅ **Variable.set() с хардкоженными секретами**
- ✅ **Секреты в строковых литералах функций**

**Файлы:** `semgrep-rules/airflow-strict/airflow-secrets-strict.yml`

### 4. BashOperator
- ✅ **Whitelist подход** - разрешены только безопасные Jinja шаблоны ({{ ds }}, {{ ts }}, {{ dag }}, etc.)
- ✅ **os.environ в bash_command** без валидации

**Файлы:** `semgrep-rules/airflow-strict/airflow-bash-whitelist.yml`

### 5. Kubernetes операторы
- ✅ **securityContext из конфига** - КРИТИЧНО
- ✅ **serviceAccountName из конфига** - КРИТИЧНО
- ✅ **volume_mounts из конфига**
- ✅ **namespace из конфига**

**Файлы:** `semgrep-rules/airflow-strict/airflow-k8s-strict.yml`

### 6. XCom pickle
- ✅ **Изменен severity с WARNING на ERROR**

**Файлы:** `semgrep-rules/airflow/airflow-xcom-pickle.yml` (обновлен)

---

## 🟡 ОСЛАБЛЕНЫ (исключены или понижен severity)

### 1. HTTP запросы
- ❌ **Исключены:** `python.requests.best-practice.use-timeout`
- ❌ **Исключены:** `python.urllib3.best-practice.urllib3-disable-warnings`
- **Причина:** В DAG файлах часто используются внутренние сервисы без SSL проверки

### 2. Generic Python lint правила
- ❌ **Исключены:** Неиспользуемые переменные
- ❌ **Исключены:** Неиспользуемые импорты
- ❌ **Исключены:** Слишком большие функции
- ❌ **Исключены:** Слишком длинные строки
- **Причина:** Это задача линтеров (flake8, ruff, pylint), не Semgrep

### 3. Общие правила о файлах
- ✅ **Оставлены:** Path traversal проверки
- ❌ **Исключены:** Общие предупреждения о работе с файлами
- **Причина:** В DAG файлах работа с файлами - нормальная практика

### 4. Стандартный набор p/python
- ❌ **Исключен полностью** из конфигурации
- **Причина:** Слишком много lint правил, не относящихся к security

---

## 📁 Структура файлов

```
semgrep-rules/
├── airflow/                    # Базовые правила
│   ├── airflow-bash-unsafe.yml
│   ├── airflow-sql-injection.yml
│   ├── airflow-rce-eval-exec.yml
│   ├── airflow-secrets.yml
│   ├── airflow-k8s-operator.yml
│   └── airflow-xcom-pickle.yml (обновлен: ERROR вместо WARNING)
│
└── airflow-strict/             # Усиленные правила
    ├── airflow-rce-strict.yml
    ├── airflow-sql-injection-strict.yml
    ├── airflow-secrets-strict.yml
    ├── airflow-bash-whitelist.yml
    └── airflow-k8s-strict.yml

semgrep-exclusions.yml          # Файл с исключениями для стандартных правил
```

---

## 🎯 Приоритеты

### Высокий приоритет (уже реализовано):
1. ✅ Усиление eval/exec (везде)
2. ✅ Усиление SQL (любая конкатенация)
3. ✅ Усиление секретов (ERROR для всех)
4. ✅ Ослабление requests/urllib3
5. ✅ Ослабление generic Python lint

### Средний приоритет (реализовано):
1. ✅ BashOperator whitelist
2. ✅ K8s securityContext, serviceAccountName
3. ✅ XCom pickle → ERROR
4. ✅ Исключение p/python

### Низкий приоритет (можно добавить позже):
1. Whitelist для K8s образов (нужен баланс между безопасностью и гибкостью)
2. Улучшенная проверка subprocess без shell=True (уже есть базовая)

---

## 📊 Сравнительная таблица

| Правило | Было | Стало | Статус |
|---------|------|-------|--------|
| eval/exec в python_callable | ERROR | ERROR (везде) | ✅ Усилено |
| SQL конкатенация | ERROR (частично) | ERROR (любая) | ✅ Усилено |
| Секреты в коде | ERROR/WARNING | ERROR (всегда) | ✅ Усилено |
| BashOperator с Jinja | ERROR | ERROR (whitelist) | ✅ Усилено |
| requests без verify | WARNING | Исключено | ✅ Ослаблено |
| Работа с файлами | WARNING | Исключено (кроме path traversal) | ✅ Ослаблено |
| Неиспользуемые переменные | INFO | Исключено | ✅ Ослаблено |
| XCom pickle | WARNING | ERROR | ✅ Усилено |
| K8s securityContext | Не проверялось | ERROR | ✅ Добавлено |
| p/python набор | Включен | Исключен | ✅ Ослаблено |

---

## 🚀 Использование

### Базовая конфигурация (все правила):
```bash
semgrep --config=.semgrep.yml dags/
```

### Только базовые правила:
```bash
semgrep --config=semgrep-rules/airflow/ dags/
```

### Только усиленные правила:
```bash
semgrep --config=semgrep-rules/airflow-strict/ dags/
```

### С исключениями:
```bash
semgrep --config=.semgrep.yml --exclude=semgrep-exclusions.yml dags/
```

---

## 📝 Заметки

- **Баланс:** Найден баланс между безопасностью и практичностью
- **Whitelist подход:** Используется для BashOperator и может быть расширен для K8s образов
- **Контекст:** Правила учитывают специфику DAG файлов
- **Разделение ответственности:** Semgrep фокусируется на security, линтеры - на code quality

