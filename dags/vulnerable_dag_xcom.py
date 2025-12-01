"""
Пример DAG с небезопасным использованием XCom с pickle
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago

default_args = {
    'owner': 'airflow',
    'start_date': days_ago(1),
}

dag_pickle = DAG(
    'vulnerable_xcom_pickle_dag',
    default_args=default_args,
    description='DAG с enable_xcom_pickling=True',
    schedule_interval=None,
)

def task_with_pickle_xcom(**context):
    # Использование XCom с pickle (если включен)
    context['ti'].xcom_push(key='data', value={'some': 'data'})
    return True

# УЯЗВИМОСТЬ 1: enable_xcom_pickling=True в PythonOperator
task_xcom_pickle = PythonOperator(
    task_id='xcom_pickle_task',
    python_callable=task_with_pickle_xcom,
    enable_xcom_pickling=True,  # ОПАСНО!
    dag=dag_pickle,
)

# УЯЗВИМОСТЬ 2: enable_xcom_pickling = True (альтернативный синтаксис)
task_xcom_pickle2 = PythonOperator(
    task_id='xcom_pickle_task2',
    python_callable=task_with_pickle_xcom,
    enable_xcom_pickling = True,  # ОПАСНО!
    dag=dag_pickle,
)

# УЯЗВИМОСТЬ 3: enable_xcom_pickling в словаре параметров
task_params = {
    'task_id': 'xcom_pickle_task3',
    'python_callable': task_with_pickle_xcom,
    'enable_xcom_pickling': True,  # ОПАСНО!
    'dag': dag_pickle,
}
task_xcom_pickle3 = PythonOperator(**task_params)

# УЯЗВИМОСТЬ 4: xcom_backend с pickle
# В реальности это настраивается в airflow.cfg, но может быть в коде
xcom_backend = "custom.pickle.xcom_backend.PickleXComBackend"  # ОПАСНО! Backend с pickle
# Или через Variable:
# xcom_backend = Variable.get("xcom_backend")  # Может содержать "pickle"

dag_pickle_backend = DAG(
    'vulnerable_xcom_backend_dag',
    default_args=default_args,
    description='DAG с pickle-based XCom backend',
    schedule_interval=None,
)
