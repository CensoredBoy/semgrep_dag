"""
Тест для правила: airflow-hardcoded-api-key
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_hardcoded_api_key', default_args=default_args, schedule_interval=None)

API_KEY = "sk_live_51Hq3kL2K3J4m5N6o7P8q9R0s1T2u3V4w5X6y7Z8"  # ОПАСНО!
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # ОПАСНО!
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # ОПАСНО!

def call_api():
    import requests
    headers = {"Authorization": f"Bearer {API_KEY}"}  # ОПАСНО!
    response = requests.get("https://api.example.com/data", headers=headers)
    return response.json()

task_api_key = PythonOperator(task_id='api_key', python_callable=call_api, dag=dag)
