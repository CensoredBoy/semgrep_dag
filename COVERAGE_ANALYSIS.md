# Анализ покрытия правил тестовыми DAG файлами

## 📊 Статистика

**Всего правил:** 43  
**Покрыто:** 43 правила  
**Не покрыто:** 0 правил  
**Покрытие:** ~100% ✅

**Обновлено:** Добавлены все недостающие примеры в тестовые DAG файлы.

---

## ✅ ПОКРЫТЫЕ ПРАВИЛА

### RCE уязвимости (vulnerable_dag_rce.py)
- ✅ `airflow-eval-in-python-callable` - eval в python_callable
- ✅ `airflow-exec-in-python-callable` - exec в python_callable
- ✅ `airflow-pickle-loads` - pickle.loads в python_callable
- ✅ `airflow-os-system` - os.system в python_callable
- ✅ `airflow-subprocess-shell-true` - subprocess с shell=True
- ✅ `airflow-eval-anywhere` - eval везде (усиленное)
- ✅ `airflow-exec-anywhere` - exec везде (усиленное)
- ✅ `airflow-pickle-anywhere` - pickle везде (усиленное)
- ✅ `airflow-subprocess-from-conf` - subprocess с данными из конфига

### BashOperator/SSHOperator (vulnerable_dag_injections.py)
- ✅ `airflow-bash-unsafe-jinja-conf` - BashOperator с dag_run.conf
- ✅ `airflow-bash-unsafe-jinja-params` - BashOperator с params
- ✅ `airflow-bash-unsafe-jinja-xcom` - BashOperator с XCom
- ✅ `airflow-ssh-unsafe-command` - SSHOperator с динамической командой
- ✅ `airflow-bash-jinja-whitelist` - BashOperator whitelist (перекрывает выше)

### SQL-инъекции (vulnerable_dag_sqli.py)
- ✅ `airflow-sql-concat-fstring` - SQL с f-строкой
- ✅ `airflow-sql-concat-plus` - SQL с конкатенацией (+)
- ✅ `airflow-sql-from-conf` - SQL из dag_run.conf
- ✅ `airflow-sql-from-xcom` - SQL из XCom
- ✅ `airflow-sql-any-concat` - Любая конкатенация SQL (усиленное)

### Секреты (vulnerable_dag_secrets.py)
- ✅ `airflow-hardcoded-password-variable` - Хардкоженный пароль
- ✅ `airflow-hardcoded-api-key` - Хардкоженный API ключ
- ✅ `airflow-connection-password-hardcoded` - Пароль в Connection
- ✅ `airflow-connection-extra-private-key` - Приватный ключ в Connection
- ✅ `airflow-jwt-token-hardcoded` - JWT токен

### K8s/Docker операторы (vulnerable_dag_injections.py)
- ✅ `airflow-k8s-unsafe-image` - K8s с динамическим image
- ✅ `airflow-k8s-unsafe-env` - K8s с динамическими env_vars
- ✅ `airflow-k8s-unsafe-volumes` - K8s с динамическими volumes
- ✅ `airflow-docker-unsafe-image` - Docker с динамическим image

---

## ✅ ВСЕ ПРАВИЛА ПОКРЫТЫ!

Все правила теперь покрыты тестовыми примерами. Добавлены следующие примеры:

## 📝 ДОБАВЛЕННЫЕ ПРИМЕРЫ

### vulnerable_dag_rce.py
- ✅ `marshal.loads()` в python_callable
- ✅ `marshal.loads()` вне python_callable (для усиленного правила)

### vulnerable_dag_sqli.py
- ✅ SQL с `.format()`
- ✅ SQL из `Variable.get()`
- ✅ SQL из `os.environ`

### vulnerable_dag_secrets.py
- ✅ Секреты в комментариях
- ✅ `Variable.set()` с секретом
- ✅ Секреты в вызовах функций

### vulnerable_dag_injections.py
- ✅ `os.environ` в BashOperator
- ✅ K8s `security-context` из конфига
- ✅ K8s `service-account` из конфига
- ✅ K8s `volume-mounts` из конфига
- ✅ K8s `namespace` из конфига

### vulnerable_dag_xcom.py (новый файл)
- ✅ `enable_xcom_pickling=True` в PythonOperator
- ✅ `enable_xcom_pickling = True` (альтернативный синтаксис)
- ✅ `enable_xcom_pickling` в словаре параметров
- ✅ `xcom_backend` с pickle

---

## ❌ ПРЕЖДЕ НЕ ПОКРЫТЫЕ ПРАВИЛА (теперь покрыты)

### RCE уязвимости
1. ❌ `airflow-marshal-loads` - marshal.loads в python_callable
   - **Статус:** Импортирован, но не используется
   - **Нужно добавить:** Пример использования marshal.loads()

2. ❌ `airflow-marshal-anywhere` - marshal.loads везде (усиленное)
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример использования marshal.loads() вне python_callable

### SQL-инъекции
3. ❌ `airflow-sql-concat-format` - SQL с .format()
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример SQL с использованием .format()

4. ❌ `airflow-sql-from-variable` - SQL из Variable.get()
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример SQL, построенного из Variable.get()

5. ❌ `airflow-sql-from-env` - SQL из os.environ
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример SQL, построенного из переменных окружения

### Секреты
6. ❌ `airflow-secrets-in-comments` - Секреты в комментариях
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример секрета в комментарии

7. ❌ `airflow-variable-set-secret` - Variable.set() с секретом
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример Variable.set() с хардкоженным секретом

8. ❌ `airflow-secrets-in-function-calls` - Секреты в вызовах функций
   - **Статус:** Частично покрыто (есть в Connection)
   - **Нужно добавить:** Больше примеров секретов в параметрах функций

### BashOperator
9. ❌ `airflow-bash-os-environ` - os.environ в bash_command
   - **Статус:** Не покрыто
   - **Нужно добавить:** Пример BashOperator с os.environ в команде

### K8s операторы
10. ❌ `airflow-k8s-unsafe-security-context` - securityContext из конфига
    - **Статус:** Не покрыто
    - **Нужно добавить:** Пример K8s оператора с securityContext из dag_run.conf

11. ❌ `airflow-k8s-unsafe-service-account` - serviceAccountName из конфига
    - **Статус:** Не покрыто
    - **Нужно добавить:** Пример K8s оператора с serviceAccountName из конфига

12. ❌ `airflow-k8s-unsafe-volume-mounts` - volume_mounts из конфига
    - **Статус:** Не покрыто
    - **Нужно добавить:** Пример K8s оператора с volume_mounts из конфига

13. ❌ `airflow-k8s-unsafe-namespace` - namespace из конфига
    - **Статус:** Не покрыто
    - **Нужно добавить:** Пример K8s оператора с namespace из конфига

### XCom
14. ❌ `airflow-xcom-pickle-enabled` - enable_xcom_pickling=True
    - **Статус:** Не покрыто
    - **Нужно добавить:** Пример с enable_xcom_pickling=True

15. ❌ `airflow-xcom-backend-pickle` - pickle-based XCom backend
    - **Статус:** Не покрыто
    - **Нужно добавить:** Пример с xcom_backend, использующим pickle

---

## 📝 Рекомендации

### Высокий приоритет (критичные правила)
1. Добавить примеры для K8s операторов (security-context, service-account, volume-mounts, namespace)
2. Добавить примеры для XCom pickle (enable_xcom_pickling, xcom_backend)
3. Добавить пример marshal.loads() (импортирован, но не используется)

### Средний приоритет
4. Добавить примеры SQL с .format(), Variable.get(), os.environ
5. Добавить примеры секретов в комментариях и Variable.set()

### Низкий приоритет
6. Добавить больше примеров секретов в вызовах функций
7. Добавить пример os.environ в BashOperator

---

## 🎯 План действий

1. **Обновить vulnerable_dag_rce.py:**
   - Добавить использование marshal.loads()

2. **Обновить vulnerable_dag_sqli.py:**
   - Добавить SQL с .format()
   - Добавить SQL из Variable.get()
   - Добавить SQL из os.environ

3. **Обновить vulnerable_dag_secrets.py:**
   - Добавить секреты в комментариях
   - Добавить Variable.set() с секретом
   - Добавить больше примеров секретов в функциях

4. **Обновить vulnerable_dag_injections.py:**
   - Добавить K8s операторы с security-context, service-account, volume-mounts, namespace
   - Добавить os.environ в BashOperator

5. **Создать новый файл или обновить существующий:**
   - Добавить примеры XCom с pickle (enable_xcom_pickling, xcom_backend)

---

## 📊 Итоговая таблица покрытия

| Категория | Всего | Покрыто | Не покрыто | % |
|-----------|-------|---------|-----------|---|
| RCE | 11 | 9 | 2 | 82% |
| BashOperator | 6 | 5 | 1 | 83% |
| SQL | 8 | 5 | 3 | 63% |
| Секреты | 8 | 5 | 3 | 63% |
| K8s/Docker | 8 | 4 | 4 | 50% |
| XCom | 2 | 0 | 2 | 0% |
| **ИТОГО** | **43** | **28** | **15** | **65%** |

*Примечание: Некоторые правила могут перекрываться (например, базовые и усиленные), поэтому фактическое покрытие может быть выше.*

