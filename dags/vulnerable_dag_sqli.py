"""
Пример DAG с SQL-инъекциями
"""
from airflow import DAG
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.providers.mysql.operators.mysql import MySqlOperator
from airflow.providers.snowflake.operators.snowflake import SnowflakeOperator
from airflow.models import Variable
from airflow.utils.dates import days_ago
import os

default_args = {
    'owner': 'airflow',
    'start_date': days_ago(1),
}

dag = DAG(
    'vulnerable_sqli_dag',
    default_args=default_args,
    description='DAG с примерами SQL-инъекций',
    schedule_interval=None,
)

# УЯЗВИМОСТЬ 1: Конкатенация строк в PostgresOperator
def get_user_sql_unsafe(user_id):
    # ОПАСНО! SQL-инъекция
    sql = f"SELECT * FROM users WHERE id = '{user_id}'"
    return sql

task_postgres_unsafe = PostgresOperator(
    task_id='postgres_unsafe',
    postgres_conn_id='postgres_default',
    sql=get_user_sql_unsafe("1' OR '1'='1"),  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 2: Конкатенация через +
def get_user_sql_unsafe2(user_id):
    sql = "SELECT * FROM users WHERE name = '" + user_id + "'"  # ОПАСНО!
    return sql

task_postgres_unsafe2 = PostgresOperator(
    task_id='postgres_unsafe2',
    postgres_conn_id='postgres_default',
    sql=get_user_sql_unsafe2("admin'--"),
    dag=dag,
)

# УЯЗВИМОСТЬ 3: SQL из dag_run.conf без параметров
def get_sql_from_conf(**context):
    table = context['dag_run'].conf.get('table', 'users')
    sql = f"SELECT * FROM {table}"  # ОПАСНО!
    return sql

task_postgres_conf = PostgresOperator(
    task_id='postgres_conf',
    postgres_conn_id='postgres_default',
    sql=get_sql_from_conf(),
    dag=dag,
)

# УЯЗВИМОСТЬ 4: MySqlOperator с конкатенацией
task_mysql_unsafe = MySqlOperator(
    task_id='mysql_unsafe',
    mysql_conn_id='mysql_default',
    sql="DELETE FROM logs WHERE user = '" + "{{ params.user }}" + "'",  # ОПАСНО!
    dag=dag,
)

# УЯЗВИМОСТЬ 5: SnowflakeOperator с f-строкой
def get_snowflake_sql_unsafe(table_name):
    sql = f"SELECT * FROM {table_name} WHERE date = '2024-01-01'"  # ОПАСНО!
    return sql

task_snowflake_unsafe = SnowflakeOperator(
    task_id='snowflake_unsafe',
    snowflake_conn_id='snowflake_default',
    sql=get_snowflake_sql_unsafe("users; DROP TABLE users;--"),
    dag=dag,
)

# УЯЗВИМОСТЬ 6: SQL с XCom
def get_sql_with_xcom(**context):
    table = context['ti'].xcom_pull(task_ids='previous_task')
    sql = f"INSERT INTO {table} VALUES (1, 'test')"  # ОПАСНО!
    return sql

task_sql_xcom = PostgresOperator(
    task_id='sql_xcom',
    postgres_conn_id='postgres_default',
    sql=get_sql_with_xcom(),
    dag=dag,
)

# УЯЗВИМОСТЬ 7: SQL с .format()
def get_sql_with_format(user_id):
    sql = "SELECT * FROM users WHERE id = '{}'".format(user_id)  # ОПАСНО!
    return sql

task_sql_format = PostgresOperator(
    task_id='sql_format',
    postgres_conn_id='postgres_default',
    sql=get_sql_with_format("1' OR '1'='1"),
    dag=dag,
)

# УЯЗВИМОСТЬ 8: SQL из Variable.get()
def get_sql_from_variable():
    table_name = Variable.get('table_name', default_var='users')
    sql = f"SELECT * FROM {table_name}"  # ОПАСНО!
    return sql

task_sql_variable = PostgresOperator(
    task_id='sql_variable',
    postgres_conn_id='postgres_default',
    sql=get_sql_from_variable(),
    dag=dag,
)

# УЯЗВИМОСТЬ 9: SQL из os.environ
def get_sql_from_env():
    table_name = os.environ.get('TABLE_NAME', 'users')
    sql = f"SELECT * FROM {table_name}"  # ОПАСНО!
    return sql

task_sql_env = PostgresOperator(
    task_id='sql_env',
    postgres_conn_id='postgres_default',
    sql=get_sql_from_env(),
    dag=dag,
)

