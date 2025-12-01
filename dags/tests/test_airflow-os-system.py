"""
Тест для правила: airflow-os-system
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
import os

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_os_system', default_args=default_args, schedule_interval=None)

def dangerous_os_system(**context):
    command = context['dag_run'].conf.get('command', 'echo test')
    os.system(command)  # ОПАСНО!
    return True

task_os_system = PythonOperator(task_id='os_system_task', python_callable=dangerous_os_system, dag=dag)
