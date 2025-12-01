"""
Тест для правила: airflow-sql-from-variable
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.models import Variable
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_sql_from_variable', default_args=default_args, schedule_interval=None)

def get_sql_from_variable():
    table_name = Variable.get('table_name', default_var='users')
    sql = f"SELECT * FROM {table_name}"  # ОПАСНО!
    return sql

task_sql_variable = PostgresOperator(
    task_id='sql_variable',
    postgres_conn_id='postgres_default',
    sql=get_sql_from_variable(),
    dag=dag,
)
