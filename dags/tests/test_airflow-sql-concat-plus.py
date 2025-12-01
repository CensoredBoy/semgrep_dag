"""
Тест для правила: airflow-sql-concat-plus
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_concat_plus', default_args=default_args, schedule_interval=None)

def get_user_sql_unsafe(user_id):
    sql = "SELECT * FROM users WHERE name = '" + user_id + "'"  # ОПАСНО!
    return sql

task_postgres_unsafe = PostgresOperator(
    task_id='postgres_unsafe',
    postgres_conn_id='postgres_default',
    sql=get_user_sql_unsafe("admin'--"),
    dag=dag,
)
