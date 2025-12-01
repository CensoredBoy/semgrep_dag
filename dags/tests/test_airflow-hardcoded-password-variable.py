"""
Тест для правила: airflow-hardcoded-password-variable
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_hardcoded_password', default_args=default_args, schedule_interval=None)

DATABASE_PASSWORD = "super_secret_password_123"  # ОПАСНО!

def connect_to_db():
    import psycopg2
    conn = psycopg2.connect(
        host="localhost", database="mydb", user="admin",
        password=DATABASE_PASSWORD  # ОПАСНО!
    )
    return conn

task_hardcoded_password = PythonOperator(
    task_id='hardcoded_password', python_callable=connect_to_db, dag=dag,
)
