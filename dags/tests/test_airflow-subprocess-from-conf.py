"""
Тест для правила: airflow-subprocess-from-conf
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
import subprocess

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_subprocess_from_conf', default_args=default_args, schedule_interval=None)

def dangerous_subprocess(**context):
    cmd = context['dag_run'].conf.get('cmd', 'echo test')
    subprocess.Popen(cmd)  # ОПАСНО! Даже без shell=True
    return True

task_subprocess = PythonOperator(task_id='subprocess_task', python_callable=dangerous_subprocess, dag=dag)
