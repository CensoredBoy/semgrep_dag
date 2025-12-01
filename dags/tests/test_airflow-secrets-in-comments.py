"""
Тест для правила: airflow-secrets-in-comments
"""
from airflow import DAG
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_secrets_in_comments', default_args=default_args, schedule_interval=None)

# # ОПАСНО! Секрет в комментарии
# password = "super_secret_password_123"  # ОПАСНО! Секрет в комментарии
