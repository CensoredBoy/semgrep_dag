"""
Тест для правила: airflow-k8s-unsafe-volume-mounts
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_volume_mounts', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_volume_mounts = KubernetesPodOperator(
    task_id='k8s_unsafe_volume_mounts', name='test-pod-mounts', image='python:3.9',
    volume_mounts="{{ dag_run.conf['volume_mounts'] }}",  # ОПАСНО!
    namespace='default', dag=dag,
)

