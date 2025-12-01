"""
Тест для правила: airflow-connection-password-hardcoded
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_connection_password', default_args=default_args, schedule_interval=None)

def create_unsafe_connection():
    from airflow.models import Connection
    conn = Connection(
        conn_id='unsafe_conn', conn_type='postgres', host='localhost',
        login='admin', password='hardcoded_password_here',  # ОПАСНО!
    )
    return conn

task_unsafe_connection = PythonOperator(
    task_id='unsafe_connection', python_callable=create_unsafe_connection, dag=dag,
)
