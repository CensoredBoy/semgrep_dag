"""
Тест для правила: airflow-sql-from-env
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago
import os

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_from_env', default_args=default_args, schedule_interval=None)

def get_sql_from_env():
    table_name = os.environ.get('TABLE_NAME', 'users')
    sql = f"SELECT * FROM {table_name}"  # ОПАСНО!
    return sql

task_sql_env = PostgresOperator(
    task_id='sql_env',
    postgres_conn_id='postgres_default',
    sql=get_sql_from_env(),
    dag=dag,
)
