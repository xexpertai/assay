from airflow import DAG
from airflow.hooks.base import BaseHook
from airflow.operators.python import PythonOperator
from datetime import datetime


def load():
    conn = BaseHook.get_connection(conn_id="warehouse")
    return conn.login


with DAG("etl", start_date=datetime(2026, 1, 1), schedule="@daily") as dag:
    PythonOperator(task_id="load", python_callable=load)
