"""
Пример БЕЗОПАСНОГО DAG для сравнения
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago
from airflow.hooks.base import BaseHook

default_args = {
    'owner': 'airflow',
    'start_date': days_ago(1),
}

dag = DAG(
    'safe_dag_example',
    default_args=default_args,
    description='Пример безопасного DAG',
    schedule_interval=None,
)

# БЕЗОПАСНО: Использование Connection через conn_id
def safe_db_operation(**context):
    from airflow.providers.postgres.hooks.postgres import PostgresHook
    hook = PostgresHook(postgres_conn_id='postgres_default')
    # Используем параметризованные запросы
    sql = "SELECT * FROM users WHERE id = %s"
    records = hook.get_records(sql, parameters=(1,))
    return records

task_safe_db = PythonOperator(
    task_id='safe_db',
    python_callable=safe_db_operation,
    dag=dag,
)

# БЕЗОПАСНО: PostgresOperator с параметризованным SQL
task_safe_sql = PostgresOperator(
    task_id='safe_sql',
    postgres_conn_id='postgres_default',
    sql="SELECT * FROM users WHERE name = %(name)s",
    parameters={'name': 'admin'},  # Параметризованный запрос
    dag=dag,
)

# БЕЗОПАСНО: BashOperator с фиксированной командой
task_safe_bash = BashOperator(
    task_id='safe_bash',
    bash_command="echo 'Hello World'",  # Фиксированная команда
    dag=dag,
)

# БЕЗОПАСНО: Использование Secret Backend для секретов
def safe_secret_usage(**context):
    from airflow.secrets import get_variable
    # Получаем секрет из Secret Backend, а не из кода
    api_key = get_variable('api_key')
    return api_key

task_safe_secret = PythonOperator(
    task_id='safe_secret',
    python_callable=safe_secret_usage,
    dag=dag,
)

