"""
Тест для правила: airflow-sql-concat-format
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_concat_format', default_args=default_args, schedule_interval=None)

def get_sql_with_format(user_id):
    sql = "SELECT * FROM users WHERE id = '{}'".format(user_id)  # ОПАСНО!
    return sql

task_sql_format = PostgresOperator(
    task_id='sql_format',
    postgres_conn_id='postgres_default',
    sql=get_sql_with_format("1' OR '1'='1"),
    dag=dag,
)
