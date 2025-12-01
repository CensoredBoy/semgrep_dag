"""
Тест для правила: airflow-bash-unsafe-jinja-conf
"""
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_bash_unsafe_jinja_conf', default_args=default_args, schedule_interval=None)

task_bash_unsafe = BashOperator(
    task_id='bash_unsafe',
    bash_command="{{ dag_run.conf['cmd'] }}",  # ОПАСНО! RCE через HTTP
    dag=dag,
)
