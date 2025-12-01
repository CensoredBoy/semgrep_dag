"""
Тест для правила: airflow-bash-os-environ
"""
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago
import os

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_bash_os_environ', default_args=default_args, schedule_interval=None)

task_bash_env = BashOperator(
    task_id='bash_env',
    bash_command=f"echo {os.environ.get('USER_INPUT', 'default')}",  # ОПАСНО!
    dag=dag,
)
