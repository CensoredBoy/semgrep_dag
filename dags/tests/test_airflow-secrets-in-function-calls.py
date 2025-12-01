"""
Тест для правила: airflow-secrets-in-function-calls
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_secrets_in_function_calls', default_args=default_args, schedule_interval=None)

def call_api_with_secret():
    import requests
    response = requests.get(
        "https://api.example.com/data",
        headers={"Authorization": "Bearer sk_live_51Hq3kL2K3J4m5N6o7P8q9R0s1T2u3V4w5X6y7Z8"},
        auth=("admin", "super_secret_password_123")
    )
    return response.json()

task_secret_in_function = PythonOperator(
    task_id='secret_in_function', python_callable=call_api_with_secret, dag=dag,
)
