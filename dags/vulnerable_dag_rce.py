"""
Пример DAG с уязвимостями Remote Code Execution
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.utils.dates import days_ago
import os
import subprocess
import pickle
import marshal

default_args = {
    'owner': 'airflow',
    'start_date': days_ago(1),
}

dag = DAG(
    'vulnerable_rce_dag',
    default_args=default_args,
    description='DAG с примерами RCE уязвимостей',
    schedule_interval=None,
)

# УЯЗВИМОСТЬ 1: eval в python_callable
def dangerous_eval_function(**context):
    cmd = context['dag_run'].conf.get('cmd', 'print("hello")')
    result = eval(cmd)  # ОПАСНО!
    return result

task_eval = PythonOperator(
    task_id='eval_task',
    python_callable=dangerous_eval_function,
    dag=dag,
)

# УЯЗВИМОСТЬ 2: exec в python_callable
def dangerous_exec_function(**context):
    code = context['dag_run'].conf.get('code', '')
    exec(code)  # ОПАСНО!
    return True

task_exec = PythonOperator(
    task_id='exec_task',
    python_callable=dangerous_exec_function,
    dag=dag,
)

# УЯЗВИМОСТЬ 3: pickle.loads с данными из конфига
def dangerous_pickle_function(**context):
    pickled_data = context['dag_run'].conf.get('pickled_data', '')
    obj = pickle.loads(pickled_data.encode())  # ОПАСНО!
    return obj

task_pickle = PythonOperator(
    task_id='pickle_task',
    python_callable=dangerous_pickle_function,
    dag=dag,
)

# УЯЗВИМОСТЬ 3.1: marshal.loads с данными из конфига
def dangerous_marshal_function(**context):
    marshaled_data = context['dag_run'].conf.get('marshaled_data', '')
    obj = marshal.loads(marshaled_data.encode())  # ОПАСНО!
    return obj

task_marshal = PythonOperator(
    task_id='marshal_task',
    python_callable=dangerous_marshal_function,
    dag=dag,
)

# УЯЗВИМОСТЬ 3.2: marshal.loads вне python_callable (для усиленного правила)
def some_function():
    data = b'\x80\x03]q\x00.'
    obj = marshal.loads(data)  # ОПАСНО! (усиленное правило)
    return obj

# УЯЗВИМОСТЬ 4: os.system
def dangerous_os_system(**context):
    command = context['dag_run'].conf.get('command', 'echo test')
    os.system(command)  # ОПАСНО!
    return True

task_os_system = PythonOperator(
    task_id='os_system_task',
    python_callable=dangerous_os_system,
    dag=dag,
)

# УЯЗВИМОСТЬ 5: subprocess с shell=True
def dangerous_subprocess(**context):
    cmd = context['dag_run'].conf.get('cmd', 'echo test')
    subprocess.Popen(cmd, shell=True)  # ОПАСНО!
    return True

task_subprocess = PythonOperator(
    task_id='subprocess_task',
    python_callable=dangerous_subprocess,
    dag=dag,
)

# УЯЗВИМОСТЬ 6: BashOperator с Jinja из dag_run.conf
task_bash_unsafe = BashOperator(
    task_id='bash_unsafe',
    bash_command="{{ dag_run.conf['cmd'] }}",  # ОПАСНО! RCE через HTTP
    dag=dag,
)

# УЯЗВИМОСТЬ 7: BashOperator с XCom
task_bash_xcom = BashOperator(
    task_id='bash_xcom',
    bash_command="echo {{ ti.xcom_pull(task_ids='previous_task') }}",  # ОПАСНО!
    dag=dag,
)

