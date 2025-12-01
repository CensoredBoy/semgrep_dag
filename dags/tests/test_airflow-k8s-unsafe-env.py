"""
Тест для правила: airflow-k8s-unsafe-env
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_env', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_env = KubernetesPodOperator(
    task_id='k8s_unsafe_env', name='test-pod-env', image='python:3.9',
    env_vars="{{ dag_run.conf['env_vars'] }}",  # ОПАСНО!
    namespace='default', dag=dag,
)
