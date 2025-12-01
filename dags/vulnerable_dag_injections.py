"""
Пример DAG с инъекциями через BashOperator, SSHOperator, K8s операторы
"""
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.providers.ssh.operators.ssh import SSHOperator
from airflow.providers.cncf.kubernetes.operators.kubernetes_pod import KubernetesPodOperator
from airflow.providers.docker.operators.docker import DockerOperator
from airflow.utils.dates import days_ago
import os

default_args = {
    'owner': 'airflow',
    'start_date': days_ago(1),
}

dag = DAG(
    'vulnerable_injections_dag',
    default_args=default_args,
    description='DAG с примерами инъекций через операторы',
    schedule_interval=None,
)

# УЯЗВИМОСТЬ 1: BashOperator с Jinja из dag_run.conf
task_bash_conf = BashOperator(
    task_id='bash_conf_injection',
    bash_command="echo {{ dag_run.conf['user_input'] }}",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 2: BashOperator с params
task_bash_params = BashOperator(
    task_id='bash_params_injection',
    bash_command="rm -rf {{ params.path }}",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 3: BashOperator с XCom
task_bash_xcom = BashOperator(
    task_id='bash_xcom_injection',
    bash_command="curl {{ ti.xcom_pull(task_ids='prev') }}",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 4: SSHOperator с динамической командой
task_ssh_unsafe = SSHOperator(
    task_id='ssh_unsafe',
    ssh_conn_id='ssh_default',
    command="{{ dag_run.conf['remote_cmd'] }}",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 5: KubernetesPodOperator с image из конфига
task_k8s_unsafe_image = KubernetesPodOperator(
    task_id='k8s_unsafe_image',
    name='test-pod',
    image="{{ dag_run.conf['image'] }}",  # ОПАСНО! Может быть любой образ
    namespace='default',
    dag=dag,
)

# УЯЗВИМОСТЬ 6: KubernetesPodOperator с env из конфига
task_k8s_unsafe_env = KubernetesPodOperator(
    task_id='k8s_unsafe_env',
    name='test-pod-env',
    image='python:3.9',
    env_vars="{{ dag_run.conf['env_vars'] }}",  # ОПАСНО!
    namespace='default',
    dag=dag,
)

# УЯЗВИМОСТЬ 7: KubernetesPodOperator с volume из конфига
task_k8s_unsafe_volume = KubernetesPodOperator(
    task_id='k8s_unsafe_volume',
    name='test-pod-volume',
    image='python:3.9',
    volumes="{{ dag_run.conf['volumes'] }}",  # ОПАСНО!
    namespace='default',
    dag=dag,
)

# УЯЗВИМОСТЬ 8: DockerOperator с image из конфига
task_docker_unsafe = DockerOperator(
    task_id='docker_unsafe',
    image="{{ dag_run.conf['docker_image'] }}",  # ОПАСНО!
    api_version='auto',
    auto_remove=True,
    dag=dag,
)

# УЯЗВИМОСТЬ 9: BashOperator с множественными подстановками
task_bash_multiple = BashOperator(
    task_id='bash_multiple',
    bash_command="python script.py --input '{{ dag_run.conf['input'] }}' --output {{ params.output }}",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 10: BashOperator с os.environ
task_bash_env = BashOperator(
    task_id='bash_env',
    bash_command=f"echo {os.environ.get('USER_INPUT', 'default')}",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 11: KubernetesPodOperator с securityContext из конфига
task_k8s_unsafe_security_context = KubernetesPodOperator(
    task_id='k8s_unsafe_security_context',
    name='test-pod-security',
    image='python:3.9',
    security_context="{{ dag_run.conf['security_context'] }}",  # ОПАСНО!
    namespace='default',
    dag=dag,
)

# УЯЗВИМОСТЬ 12: KubernetesPodOperator с serviceAccountName из конфига
task_k8s_unsafe_service_account = KubernetesPodOperator(
    task_id='k8s_unsafe_service_account',
    name='test-pod-sa',
    image='python:3.9',
    service_account_name="{{ dag_run.conf['service_account'] }}",  # ОПАСНО!
    namespace='default',
    dag=dag,
)

# УЯЗВИМОСТЬ 13: KubernetesPodOperator с volume_mounts из конфига
task_k8s_unsafe_volume_mounts = KubernetesPodOperator(
    task_id='k8s_unsafe_volume_mounts',
    name='test-pod-mounts',
    image='python:3.9',
    volume_mounts="{{ dag_run.conf['volume_mounts'] }}",  # ОПАСНО!
    namespace='default',
    dag=dag,
)

# УЯЗВИМОСТЬ 14: KubernetesPodOperator с namespace из конфига
task_k8s_unsafe_namespace = KubernetesPodOperator(
    task_id='k8s_unsafe_namespace',
    name='test-pod-ns',
    image='python:3.9',
    namespace="{{ dag_run.conf['namespace'] }}",  # ОПАСНО!
    dag=dag,
)

