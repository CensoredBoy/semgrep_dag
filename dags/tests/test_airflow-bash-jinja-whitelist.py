"""
Тест для правила: airflow-bash-jinja-whitelist
"""
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_bash_jinja_whitelist', default_args=default_args, schedule_interval=None)

task_bash_unsafe = BashOperator(
    task_id='bash_unsafe',
    bash_command="echo {{ dag_run.conf['user_input'] }}",  # ОПАСНО! Не в whitelist
    dag=dag,
)
