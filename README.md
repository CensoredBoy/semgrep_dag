# Тестирование Semgrep для Apache Airflow DAG файлов

Этот проект содержит примеры уязвимых DAG файлов и кастомные правила Semgrep для обнаружения проблем безопасности в Apache Airflow.

## Структура проекта

```
.
├── .semgrep.yml              # Конфигурация Semgrep
├── semgrep-exclusions.yml    # Исключения для стандартных правил
├── dags/                     # Примеры DAG файлов
│   ├── vulnerable_dag_rce.py          # RCE уязвимости
│   ├── vulnerable_dag_sqli.py         # SQL-инъекции
│   ├── vulnerable_dag_secrets.py      # Утечки секретов
│   ├── vulnerable_dag_injections.py   # Инъекции через операторы
│   └── safe_dag_example.py            # Пример безопасного DAG
├── semgrep-rules/            # Кастомные правила Semgrep
│   ├── airflow/              # Базовые правила
│   │   ├── airflow-bash-unsafe.yml    # Правила для BashOperator
│   │   ├── airflow-sql-injection.yml  # Правила для SQL-инъекций
│   │   ├── airflow-rce-eval-exec.yml # Правила для eval/exec
│   │   ├── airflow-secrets.yml        # Правила для секретов
│   │   ├── airflow-k8s-operator.yml    # Правила для K8s/Docker операторов
│   │   └── airflow-xcom-pickle.yml    # Правила для XCom pickle
│   └── airflow-strict/       # Усиленные правила
│       ├── airflow-rce-strict.yml              # Усиленные правила RCE
│       ├── airflow-sql-injection-strict.yml    # Усиленные правила SQL
│       ├── airflow-secrets-strict.yml         # Усиленные правила секретов
│       ├── airflow-bash-whitelist.yml         # Whitelist для BashOperator
│       └── airflow-k8s-strict.yml              # Усиленные правила K8s
├── ANALYSIS.md               # Подробный анализ правил
├── SUMMARY.md                # Краткая сводка изменений
├── QUICKSTART.md             # Быстрый старт
├── README.md                 # Этот файл
└── run_semgrep.sh            # Скрипт для запуска анализа
```

## Установка Semgrep

### Через pip
```bash
pip install semgrep
```

### Через Homebrew (macOS)
```bash
brew install semgrep
```

### Через Docker
```bash
docker pull returntocorp/semgrep
```

## Запуск анализа

### Базовый запуск
```bash
semgrep --config=.semgrep.yml dags/
```

### С выводом в JSON
```bash
semgrep --config=.semgrep.yml --json dags/ > results.json
```

### С выводом в SARIF (для интеграции с GitHub/GitLab)
```bash
semgrep --config=.semgrep.yml --sarif dags/ > results.sarif
```

### Только кастомные правила
```bash
semgrep --config=semgrep-rules/airflow/ dags/
```

### Только стандартные правила
```bash
semgrep --config=p/security-audit --config=p/secrets dags/
```

## Описание уязвимостей

### 1. Remote Code Execution (RCE)

**Файл:** `dags/vulnerable_dag_rce.py`

Примеры уязвимостей:
- Использование `eval()` в `python_callable`
- Использование `exec()` в `python_callable`
- Использование `pickle.loads()` с данными из конфига
- Использование `os.system()` и `subprocess` с `shell=True`
- `BashOperator` с Jinja-шаблонами из `dag_run.conf`

**Правила:** `semgrep-rules/airflow/airflow-rce-eval-exec.yml`, `semgrep-rules/airflow/airflow-bash-unsafe.yml`

### 2. SQL-инъекции

**Файл:** `dags/vulnerable_dag_sqli.py`

Примеры уязвимостей:
- Конкатенация строк в SQL запросах
- Использование f-строк для построения SQL
- SQL из `dag_run.conf` без параметризации
- SQL с данными из XCom

**Правила:** `semgrep-rules/airflow/airflow-sql-injection.yml`

### 3. Утечки секретов

**Файл:** `dags/vulnerable_dag_secrets.py`

Примеры уязвимостей:
- Хардкоженные пароли в переменных
- Хардкоженные API ключи
- Пароли в Connection объектах
- Приватные ключи в `extra` Connection

**Правила:** `semgrep-rules/airflow/airflow-secrets.yml`

### 4. Инъекции через операторы

**Файл:** `dags/vulnerable_dag_injections.py`

Примеры уязвимостей:
- `BashOperator` с динамическими командами из конфига
- `SSHOperator` с командами из параметров
- `KubernetesPodOperator` с образами из конфига
- `DockerOperator` с образами из конфига

**Правила:** `semgrep-rules/airflow/airflow-bash-unsafe.yml`, `semgrep-rules/airflow/airflow-k8s-operator.yml`

## Анализ правил: что усилить, что ослабить

📋 **Подробный анализ:** См. файл `ANALYSIS.md` с полным анализом того, какие правила нужно усилить, а какие ослабить для DAG файлов.

📊 **Краткая сводка:** См. файл `SUMMARY.md` с таблицей изменений.

### Основные выводы:

**🔴 Усилены (сделаны строже):**
- RCE: запрет eval/exec везде (не только в python_callable)
- SQL: запрет ЛЮБОЙ конкатенации в SQL операторах
- Секреты: ERROR для всех случаев, включая комментарии
- BashOperator: whitelist подход для Jinja шаблонов
- K8s: проверка securityContext, serviceAccountName, namespace
- XCom pickle: изменен с WARNING на ERROR

**🟡 Ослаблены (исключены):**
- HTTP запросы (requests, urllib3) - норма для DAG
- Generic Python lint правила - задача линтеров
- Общие правила о файлах (кроме path traversal)
- Стандартный набор p/python - исключен полностью

## Кастомные правила Semgrep

### Базовые правила (semgrep-rules/airflow/)

### airflow-bash-unsafe.yml
Обнаруживает небезопасное использование `BashOperator` и `SSHOperator` с динамическими командами из:
- `dag_run.conf`
- `params`
- XCom (`ti.xcom_pull`)

### airflow-sql-injection.yml
Обнаруживает SQL-инъекции в операторах:
- `PostgresOperator`
- `MySqlOperator`
- `SnowflakeOperator`
- `BigQueryInsertJobOperator`
- Любые кастомные `*SqlOperator`

Проверяет:
- Конкатенацию строк (`+`)
- f-строки
- `.format()`
- SQL из конфигов/XCom

### airflow-rce-eval-exec.yml
Обнаруживает опасные конструкции в `python_callable`:
- `eval()`
- `exec()`
- `pickle.loads()`
- `marshal.loads()`
- `os.system()`
- `subprocess` с `shell=True`

### airflow-secrets.yml
Обнаруживает хардкоженные секреты:
- Пароли в переменных
- API ключи
- JWT токены
- Креды в Connection объектах

### airflow-k8s-operator.yml
Обнаруживает небезопасное использование:
- `KubernetesPodOperator` с динамическими `image`, `env_vars`, `volumes`
- `DockerOperator` с динамическими `image`

### airflow-xcom-pickle.yml
Предупреждает об использовании pickle для XCom (может привести к RCE). **Severity: ERROR** (усилено)

### Усиленные правила (semgrep-rules/airflow-strict/)

### airflow-rce-strict.yml
Усиленные правила для RCE:
- Запрет eval/exec везде (не только в python_callable)
- Запрет pickle/marshal везде
- subprocess с данными из конфига (даже без shell=True)

### airflow-sql-injection-strict.yml
Усиленные правила для SQL-инъекций:
- Запрет ЛЮБОЙ конкатенации (f-строки, +, format, %)
- SQL из Variable.get() без валидации
- SQL из os.environ без валидации
- Расширенный список операторов

### airflow-secrets-strict.yml
Усиленные правила для секретов:
- Секреты в комментариях
- Variable.set() с хардкоженными секретами
- Секреты в строковых литералах функций

### airflow-bash-whitelist.yml
Whitelist подход для BashOperator:
- Разрешены только безопасные Jinja шаблоны ({{ ds }}, {{ ts }}, {{ dag }}, etc.)
- Запрет os.environ в bash_command без валидации

### airflow-k8s-strict.yml
Усиленные правила для Kubernetes операторов:
- securityContext из конфига - КРИТИЧНО
- serviceAccountName из конфига - КРИТИЧНО
- volume_mounts из конфига
- namespace из конфига

## Интеграция в CI/CD

### GitHub Actions

```yaml
name: Semgrep Security Scan

on: [push, pull_request]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            .semgrep.yml
          generateSarif: "1"
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif
```

### GitLab CI

```yaml
semgrep:
  image: returntocorp/semgrep
  script:
    - semgrep --config=.semgrep.yml --json dags/ > semgrep-report.json
  artifacts:
    reports:
      sast: semgrep-report.json
```

## Рекомендации по использованию

1. **Включите в pre-commit hook:**
   ```bash
   semgrep --config=.semgrep.yml --error dags/
   ```

2. **Настройте уровни серьезности:**
   - `ERROR` - блокирующие проблемы (RCE, SQLi, секреты, K8s securityContext)
   - `WARNING` - потенциальные проблемы (ослаблено для DAG)

3. **Используйте исключения при необходимости:**
   ```bash
   semgrep --config=.semgrep.yml --exclude=semgrep-exclusions.yml dags/
   ```

4. **Только базовые правила (если усиленные слишком строгие):**
   ```bash
   semgrep --config=semgrep-rules/airflow/ dags/
   ```

5. **Только усиленные правила (максимальная безопасность):**
   ```bash
   semgrep --config=semgrep-rules/airflow-strict/ dags/
   ```

6. **Используйте только для DAG файлов:**
   Правила настроены специально для Airflow DAG, не применяйте их к другому коду.

## Примеры безопасных практик

См. файл `dags/safe_dag_example.py` для примеров:
- Параметризованные SQL запросы
- Использование Secret Backend для секретов
- Фиксированные команды в BashOperator
- Использование Connection через `conn_id`

## Дополнительные ресурсы

- [Semgrep документация](https://semgrep.dev/docs/)
- [Apache Airflow Security Best Practices](https://airflow.apache.org/docs/apache-airflow/stable/security/index.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Лицензия

Этот проект создан для образовательных целей и демонстрации возможностей Semgrep для анализа безопасности Airflow DAG файлов.

