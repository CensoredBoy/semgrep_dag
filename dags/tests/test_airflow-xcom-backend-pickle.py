"""
Тест для правила: airflow-xcom-backend-pickle
"""
from airflow import DAG
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_xcom_backend_pickle', default_args=default_args, schedule_interval=None)

# В реальности это настраивается в airflow.cfg, но может быть в коде
xcom_backend = "custom.pickle.xcom_backend.PickleXComBackend"  # ОПАСНО! Backend с pickle

