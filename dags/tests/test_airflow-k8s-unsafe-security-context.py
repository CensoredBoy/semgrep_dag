"""
Тест для правила: airflow-k8s-unsafe-security-context
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_security_context', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_security_context = KubernetesPodOperator(
    task_id='k8s_unsafe_security_context', name='test-pod-security', image='python:3.9',
    security_context="{{ dag_run.conf['security_context'] }}",  # ОПАСНО!
    namespace='default', dag=dag,
)
