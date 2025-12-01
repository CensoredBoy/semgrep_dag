#!/bin/bash

# Скрипт для запуска ВСЕХ проверок Semgrep сразу
# Включает: стандартные правила + базовые кастомные + усиленные кастомные

set -e

echo "🔍 Запуск ВСЕХ проверок Semgrep для Airflow DAG"
echo "=============================================="
echo ""

# Проверка наличия semgrep
if ! command -v semgrep &> /dev/null; then
    echo "❌ Semgrep не установлен. Установите: pip install semgrep"
    exit 1
fi

# Определяем директорию для сканирования (по умолчанию dags/)
TARGET_DIR="${1:-dags/}"

echo "📋 Запускаемые проверки:"
echo "  ✅ Стандартные правила (p/security-audit, p/secrets)"
echo "  ✅ Базовые кастомные правила (semgrep-rules/airflow/)"
echo "  ✅ Усиленные кастомные правила (semgrep-rules/airflow-strict/)"
echo ""
echo "📂 Сканируемая директория: $TARGET_DIR"
echo ""

# Запуск с ВСЕМИ правилами
semgrep \
  --config=p/security-audit \
  --config=p/secrets \
  --config=semgrep-rules/airflow/ \
  --config=semgrep-rules/airflow-strict/ \
  "$TARGET_DIR"

echo ""
echo "✅ Все проверки завершены!"

