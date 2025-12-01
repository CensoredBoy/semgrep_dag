"""
Тест для правила: airflow-k8s-unsafe-volumes
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_volumes', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_volume = KubernetesPodOperator(
    task_id='k8s_unsafe_volume', name='test-pod-volume', image='python:3.9',
    volumes="{{ dag_run.conf['volumes'] }}",  # ОПАСНО!
    namespace='default', dag=dag,
)
