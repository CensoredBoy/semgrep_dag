"""
Тест для правила: airflow-sql-any-concat
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_any_concat', default_args=default_args, schedule_interval=None)

def get_sql_any_concat(user_id):
    sql = f"SELECT * FROM users WHERE id = '{user_id}'"  # ОПАСНО! Даже без конфига
    return sql

task_sql_any = PostgresOperator(
    task_id='sql_any',
    postgres_conn_id='postgres_default',
    sql=get_sql_any_concat("1' OR '1'='1"),
    dag=dag,
)
