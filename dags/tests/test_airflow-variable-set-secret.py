"""
Тест для правила: airflow-variable-set-secret
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_variable_set_secret', default_args=default_args, schedule_interval=None)

def set_secret_variable():
    Variable.set("database_password", "super_secret_password_123")  # ОПАСНО!
    return True

task_set_secret = PythonOperator(
    task_id='set_secret_variable', python_callable=set_secret_variable, dag=dag,
)
