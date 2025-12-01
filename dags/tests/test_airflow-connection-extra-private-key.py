"""
Тест для правила: airflow-connection-extra-private-key
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_connection_private_key', default_args=default_args, schedule_interval=None)

def create_unsafe_connection():
    from airflow.models import Connection
    conn = Connection(
        conn_id='unsafe_conn', conn_type='postgres', host='localhost', login='admin',
        extra={'private_key': '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----'}  # ОПАСНО!
    )
    return conn

task_unsafe_connection = PythonOperator(
    task_id='unsafe_connection', python_callable=create_unsafe_connection, dag=dag,
)
