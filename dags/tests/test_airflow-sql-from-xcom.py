"""
Тест для правила: airflow-sql-from-xcom
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_from_xcom', default_args=default_args, schedule_interval=None)

def get_sql_with_xcom(**context):
    table = context['ti'].xcom_pull(task_ids='previous_task')
    sql = f"INSERT INTO {table} VALUES (1, 'test')"  # ОПАСНО!
    return sql

task_sql_xcom = PostgresOperator(
    task_id='sql_xcom',
    postgres_conn_id='postgres_default',
    sql=get_sql_with_xcom(),
    dag=dag,
)
