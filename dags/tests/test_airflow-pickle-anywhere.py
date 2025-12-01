"""
Тест для правила: airflow-pickle-anywhere
"""
from airflow import DAG
from airflow.utils.dates import days_ago
import pickle

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_pickle_anywhere', default_args=default_args, schedule_interval=None)

data = b'\x80\x03]q\x00.'
obj = pickle.loads(data)  # ОПАСНО! (усиленное правило)
