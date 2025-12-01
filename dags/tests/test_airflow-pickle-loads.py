"""
Тест для правила: airflow-pickle-loads
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
import pickle

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_pickle_loads', default_args=default_args, schedule_interval=None)

def dangerous_pickle_function(**context):
    pickled_data = context['dag_run'].conf.get('pickled_data', '')
    obj = pickle.loads(pickled_data.encode())  # ОПАСНО!
    return obj

task_pickle = PythonOperator(task_id='pickle_task', python_callable=dangerous_pickle_function, dag=dag)
