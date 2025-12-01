"""
Тест для правила: airflow-xcom-pickle-enabled
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_xcom_pickle_enabled', default_args=default_args, schedule_interval=None)

def task_with_pickle_xcom(**context):
    context['ti'].xcom_push(key='data', value={'some': 'data'})
    return True

task_xcom_pickle = PythonOperator(
    task_id='xcom_pickle_task', python_callable=task_with_pickle_xcom,
    enable_xcom_pickling=True,  # ОПАСНО!
    dag=dag,
)

