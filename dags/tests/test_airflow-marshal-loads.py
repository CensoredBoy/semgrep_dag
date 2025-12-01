"""
Тест для правила: airflow-marshal-loads
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
import marshal

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_marshal_loads', default_args=default_args, schedule_interval=None)

def dangerous_marshal_function(**context):
    marshaled_data = context['dag_run'].conf.get('marshaled_data', '')
    obj = marshal.loads(marshaled_data.encode())  # ОПАСНО!
    return obj

task_marshal = PythonOperator(task_id='marshal_task', python_callable=dangerous_marshal_function, dag=dag)
