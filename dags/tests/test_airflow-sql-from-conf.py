"""
Тест для правила: airflow-sql-from-conf
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_from_conf', default_args=default_args, schedule_interval=None)

def get_sql_from_conf(**context):
    table = context['dag_run'].conf.get('table', 'users')
    sql = f"SELECT * FROM {table}"  # ОПАСНО!
    return sql

task_postgres_conf = PostgresOperator(
    task_id='postgres_conf',
    postgres_conn_id='postgres_default',
    sql=get_sql_from_conf(),
    dag=dag,
)
