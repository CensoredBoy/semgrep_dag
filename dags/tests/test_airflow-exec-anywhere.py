"""
Тест для правила: airflow-exec-anywhere
"""
from airflow import DAG
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_exec_anywhere', default_args=default_args, schedule_interval=None)

code = "print('hello')"
exec(code)  # ОПАСНО! (усиленное правило)
