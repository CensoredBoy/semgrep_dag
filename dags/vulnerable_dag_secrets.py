"""
Пример DAG с утечками секретов и мисконфигами
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.postgres.operators.postgres import PostgresOperator
from airflow.models import Variable
from airflow.utils.dates import days_ago

default_args = {
    'owner': 'airflow',
    'start_date': days_ago(1),
}

dag = DAG(
    'vulnerable_secrets_dag',
    default_args=default_args,
    description='DAG с примерами утечек секретов',
    schedule_interval=None,
)

# УЯЗВИМОСТЬ 1: Хардкоженный пароль
DATABASE_PASSWORD = "super_secret_password_123"  # ОПАСНО!

def connect_to_db():
    import psycopg2
    conn = psycopg2.connect(
        host="localhost",
        database="mydb",
        user="admin",
        password=DATABASE_PASSWORD  # ОПАСНО!
    )
    return conn

task_hardcoded_password = PythonOperator(
    task_id='hardcoded_password',
    python_callable=connect_to_db,
    dag=dag,
)

# УЯЗВИМОСТЬ 2: Хардкоженный API ключ
  # ОПАСНО!
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # ОПАСНО!
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # ОПАСНО!

def call_api():
    import requests
    headers = {"Authorization": f"Bearer {API_KEY}"}  # ОПАСНО!
    response = requests.get("https://api.example.com/data", headers=headers)
    return response.json()

task_api_key = PythonOperator(
    task_id='api_key',
    python_callable=call_api,
    dag=dag,
)

# УЯЗВИМОСТЬ 3: Хардкоженный токен GitHub
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"  # ОПАСНО!

# УЯЗВИМОСТЬ 4: PostgresOperator с паролем в extra
task_postgres_unsafe = PostgresOperator(
    task_id='postgres_unsafe_creds',
    postgres_conn_id='postgres_default',
    sql="SELECT 1",
    dag=dag,
)

# УЯЗВИМОСТЬ 5: Connection с паролем в коде (симуляция)
def create_unsafe_connection():
    from airflow.models import Connection
    conn = Connection(
        conn_id='unsafe_conn',
        conn_type='postgres',
        host='localhost',
        login='admin',
        password='hardcoded_password_here',  # ОПАСНО!
        extra={
            'private_key': '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----'  # ОПАСНО!
        }
    )
    return conn

task_unsafe_connection = PythonOperator(
    task_id='unsafe_connection',
    python_callable=create_unsafe_connection,
    dag=dag,
)

# УЯЗВИМОСТЬ 6: JWT токен
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # ОПАСНО!

# УЯЗВИМОСТЬ 7: Секрет в комментарии
  # ОПАСНО! Секрет в комментарии

# УЯЗВИМОСТЬ 8: Variable.set() с хардкоженным секретом
def set_secret_variable():
    Variable.set("database_password", "super_secret_password_123")  # ОПАСНО!
    return True

task_set_secret = PythonOperator(
    task_id='set_secret_variable',
    python_callable=set_secret_variable,
    dag=dag,
)

# УЯЗВИМОСТЬ 9: Секреты в вызовах функций
def call_api_with_secret():
    import requests
    # ОПАСНО! Секрет передается как параметр функции
    response = requests.get(
        "https://api.example.com/data",
        headers={"Authorization": "Bearer sk_live_51Hq3kL2K3J4m5N6o7P8q9R0s1T2u3V4w5X6y7Z8"},
        auth=("admin", "super_secret_password_123")
    )
    return response.json()

task_secret_in_function = PythonOperator(
    task_id='secret_in_function',
    python_callable=call_api_with_secret,
    dag=dag,
)

