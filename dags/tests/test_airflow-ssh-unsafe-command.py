"""
Тест для правила: airflow-ssh-unsafe-command
"""
from airflow import DAG
from airflow.providers.ssh.operators.ssh import SSHOperator
from airflow.utils.dates import days_ago

default_args = {'owner': 'airflow', 'start_date': days_ago(1)}
dag = DAG('test_ssh_unsafe_command', default_args=default_args, schedule_interval=None)

task_ssh_unsafe = SSHOperator(
    task_id='ssh_unsafe',
    ssh_conn_id='ssh_default',
    command="{{ dag_run.conf['remote_cmd'] }}",  # ОПАСНО!
    dag=dag,
)
