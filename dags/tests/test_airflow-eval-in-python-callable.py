"""
Тест для правила: airflow-eval-in-python-callable
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_eval_in_python_callable', default_args=default_args, schedule_interval=None)

def dangerous_eval_function(**context):
    cmd = context['dag_run'].conf.get('cmd', 'print("hello")')
    result = eval(cmd)  # ОПАСНО!
    return result

task_eval = PythonOperator(task_id='eval_task', python_callable=dangerous_eval_function, dag=dag)
