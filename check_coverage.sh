#!/bin/bash

echo "📊 ПРОВЕРКА ПОКРЫТИЯ ПРАВИЛ ТЕСТОВЫМИ DAG"
echo "========================================"
echo ""

# Правила, которые должны быть покрыты
declare -A rules_coverage=(
    # RCE
    ["airflow-eval-in-python-callable"]="vulnerable_dag_rce.py"
    ["airflow-exec-in-python-callable"]="vulnerable_dag_rce.py"
    ["airflow-pickle-loads"]="vulnerable_dag_rce.py"
    ["airflow-marshal-loads"]="MISSING"
    ["airflow-os-system"]="vulnerable_dag_rce.py"
    ["airflow-subprocess-shell-true"]="vulnerable_dag_rce.py"
    ["airflow-eval-anywhere"]="vulnerable_dag_rce.py"
    ["airflow-exec-anywhere"]="vulnerable_dag_rce.py"
    ["airflow-pickle-anywhere"]="vulnerable_dag_rce.py"
    ["airflow-marshal-anywhere"]="MISSING"
    ["airflow-subprocess-from-conf"]="vulnerable_dag_rce.py"
    
    # BashOperator
    ["airflow-bash-unsafe-jinja-conf"]="vulnerable_dag_injections.py"
    ["airflow-bash-unsafe-jinja-params"]="vulnerable_dag_injections.py"
    ["airflow-bash-unsafe-jinja-xcom"]="vulnerable_dag_injections.py"
    ["airflow-ssh-unsafe-command"]="vulnerable_dag_injections.py"
    ["airflow-bash-jinja-whitelist"]="vulnerable_dag_injections.py"
    ["airflow-bash-os-environ"]="MISSING"
    
    # SQL
    ["airflow-sql-concat-fstring"]="vulnerable_dag_sqli.py"
    ["airflow-sql-concat-plus"]="vulnerable_dag_sqli.py"
    ["airflow-sql-concat-format"]="MISSING"
    ["airflow-sql-from-conf"]="vulnerable_dag_sqli.py"
    ["airflow-sql-from-xcom"]="vulnerable_dag_sqli.py"
    ["airflow-sql-any-concat"]="vulnerable_dag_sqli.py"
    ["airflow-sql-from-variable"]="MISSING"
    ["airflow-sql-from-env"]="MISSING"
    
    # Secrets
    ["airflow-hardcoded-password-variable"]="vulnerable_dag_secrets.py"
    ["airflow-hardcoded-api-key"]="vulnerable_dag_secrets.py"
    ["airflow-connection-password-hardcoded"]="vulnerable_dag_secrets.py"
    ["airflow-connection-extra-private-key"]="vulnerable_dag_secrets.py"
    ["airflow-jwt-token-hardcoded"]="vulnerable_dag_secrets.py"
    ["airflow-secrets-in-comments"]="MISSING"
    ["airflow-variable-set-secret"]="MISSING"
    ["airflow-secrets-in-function-calls"]="MISSING"
    
    # K8s
    ["airflow-k8s-unsafe-image"]="vulnerable_dag_injections.py"
    ["airflow-k8s-unsafe-env"]="vulnerable_dag_injections.py"
    ["airflow-k8s-unsafe-volumes"]="vulnerable_dag_injections.py"
    ["airflow-docker-unsafe-image"]="vulnerable_dag_injections.py"
    ["airflow-k8s-unsafe-security-context"]="MISSING"
    ["airflow-k8s-unsafe-service-account"]="MISSING"
    ["airflow-k8s-unsafe-volume-mounts"]="MISSING"
    ["airflow-k8s-unsafe-namespace"]="MISSING"
    
    # XCom
    ["airflow-xcom-pickle-enabled"]="MISSING"
    ["airflow-xcom-backend-pickle"]="MISSING"
)

covered=0
missing=0
missing_rules=()

for rule in "${!rules_coverage[@]}"; do
    if [ "${rules_coverage[$rule]}" = "MISSING" ]; then
        ((missing++))
        missing_rules+=("$rule")
    else
        ((covered++))
    fi
done

total=$((covered + missing))
coverage_percent=$((covered * 100 / total))

echo "✅ Покрыто: $covered правил"
echo "❌ Не покрыто: $missing правил"
echo "📊 Покрытие: ${coverage_percent}%"
echo ""

if [ $missing -gt 0 ]; then
    echo "❌ НЕ ПОКРЫТЫЕ ПРАВИЛА:"
    for rule in "${missing_rules[@]}"; do
        echo "   - $rule"
    done
fi

