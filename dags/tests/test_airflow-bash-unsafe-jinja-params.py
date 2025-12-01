"""
Тест для правила: airflow-bash-unsafe-jinja-params
"""
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_bash_unsafe_jinja_params', default_args=default_args, schedule_interval=None)

task_bash_params = BashOperator(
    task_id='bash_params',
    bash_command="rm -rf {{ params.path }}",  # ОПАСНО!
    dag=dag,
)
