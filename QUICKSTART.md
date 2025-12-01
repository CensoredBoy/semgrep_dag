# Быстрый старт

## Установка Semgrep

```bash
# Через pip
pip install semgrep

# Или через Homebrew (macOS)
brew install semgrep
```

## Запуск анализа

```bash
# Простой запуск
./run_semgrep.sh

# С сохранением в JSON
./run_semgrep.sh --json

# С сохранением в SARIF
./run_semgrep.sh --sarif

# Или напрямую через semgrep
semgrep --config=.semgrep.yml dags/
```

## Что будет обнаружено

Semgrep найдет уязвимости в следующих файлах:

- ✅ `dags/vulnerable_dag_rce.py` - RCE через eval/exec/pickle
- ✅ `dags/vulnerable_dag_sqli.py` - SQL-инъекции
- ✅ `dags/vulnerable_dag_secrets.py` - Хардкоженные секреты
- ✅ `dags/vulnerable_dag_injections.py` - Инъекции через операторы
- ❌ `dags/safe_dag_example.py` - Безопасный код (не должен вызывать ошибок)

## Ожидаемый результат

После запуска вы увидите множество предупреждений и ошибок для уязвимых DAG файлов, что подтверждает работу правил Semgrep.

