"""
Тест для правила: airflow-k8s-unsafe-service-account
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_service_account', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_service_account = KubernetesPodOperator(
    task_id='k8s_unsafe_service_account', name='test-pod-sa', image='python:3.9',
    service_account_name="{{ dag_run.conf['service_account'] }}",  # ОПАСНО!
    namespace='default', dag=dag,
)
