"""
Тест для правила: airflow-exec-in-python-callable
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_exec_in_python_callable', default_args=default_args, schedule_interval=None)

def dangerous_exec_function(**context):
    code = context['dag_run'].conf.get('code', '')
    exec(code)  # ОПАСНО!
    return True

task_exec = PythonOperator(task_id='exec_task', python_callable=dangerous_exec_function, dag=dag)
