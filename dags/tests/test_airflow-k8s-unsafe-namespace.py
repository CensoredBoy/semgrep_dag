"""
Тест для правила: airflow-k8s-unsafe-namespace
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_namespace', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_namespace = KubernetesPodOperator(
    task_id='k8s_unsafe_namespace', name='test-pod-ns', image='python:3.9',
    namespace="{{ dag_run.conf['namespace'] }}",  # ОПАСНО!
    dag=dag,
)

