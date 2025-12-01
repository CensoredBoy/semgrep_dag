"""
Тест для правила: airflow-docker-unsafe-image
"""
from airflow import DAG
from airflow.providers.docker.operators.docker import DockerOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_docker_unsafe_image', default_args=default_args, schedule_interval=None)

task_docker_unsafe = DockerOperator(
    task_id='docker_unsafe',
    image="{{ dag_run.conf['docker_image'] }}",  # ОПАСНО!
    api_version='auto', auto_remove=True, dag=dag,
)
