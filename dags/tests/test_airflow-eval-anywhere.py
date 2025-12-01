"""
Тест для правила: airflow-eval-anywhere
"""
from airflow import DAG
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_eval_anywhere', default_args=default_args, schedule_interval=None)

cmd = "print('hello')"
result = eval(cmd)  # ОПАСНО! (усиленное правило)
