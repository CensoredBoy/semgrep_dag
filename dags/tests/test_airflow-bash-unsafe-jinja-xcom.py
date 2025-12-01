"""
Тест для правила: airflow-bash-unsafe-jinja-xcom
"""
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_bash_unsafe_jinja_xcom', default_args=default_args, schedule_interval=None)

task_bash_xcom = BashOperator(
    task_id='bash_xcom',
    bash_command="echo {{ ti.xcom_pull(task_ids='previous_task') }}",  # ОПАСНО!
    dag=dag,
)
