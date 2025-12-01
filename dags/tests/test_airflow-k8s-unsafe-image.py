"""
Тест для правила: airflow-k8s-unsafe-image
"""
from airflow import DAG
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_k8s_unsafe_image', default_args=default_args, schedule_interval=None)

task_k8s_unsafe_image = KubernetesPodOperator(
    task_id='k8s_unsafe_image', name='test-pod',
    image="{{ dag_run.conf['image'] }}",  # ОПАСНО! Может быть любой образ
    namespace='default', dag=dag,
)
