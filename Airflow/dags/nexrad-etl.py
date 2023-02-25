import os
import sqlite3
from datetime import timedelta

import boto3
from airflow.operators.python_operator import PythonOperator
from airflow.providers.google.cloud.hooks.gcs import GCSHook
from airflow.utils.dates import days_ago
from google.cloud import storage
from google.oauth2.service_account import Credentials

from airflow import DAG

default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "start_date": days_ago(1),
    "retries": 1,
    "execution_timeout": timedelta(hours=1),
}

dag = DAG(
    "nexrad_ETL",
    default_args=default_args,
    schedule_interval="30 1 * * *",  # runs every day at 1am
)


def nexrad_ETL():
    AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY")
    AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")

    bucket = "noaa-nexrad-level2"
    year_list = []
    year_month_list = []
    year_month_day = []
    year_month_day_station_code = set()

    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )

    prefix = ""
    result = client.list_objects(Bucket=bucket, Prefix=prefix, Delimiter="/")
    for o in result.get("CommonPrefixes"):
        year_list.append(o.get("Prefix"))

    for year in year_list:
        prefix = year
        result = client.list_objects(Bucket=bucket, Prefix=prefix, Delimiter="/")
        for o in result.get("CommonPrefixes"):
            year_month_list.append(o.get("Prefix"))

    for year_month in year_month_list:
        prefix = year_month
        result = client.list_objects(Bucket=bucket, Prefix=prefix, Delimiter="/")
        for o in result.get("CommonPrefixes"):
            year_month_day.append(o.get("Prefix"))

    for year_month_day in year_month_day:
        prefix = year_month_day
        result = client.list_objects(Bucket=bucket, Prefix=prefix, Delimiter="/")
        for o in result.get("CommonPrefixes"):
            meta_data = o.get("Prefix").split("/")
            year_month_day_station_code.add(
                (meta_data[0], meta_data[1], meta_data[2], meta_data[3])
            )

    bucket_name = "db_bucket_damg7245"
    # Replace [DATABASE_FILE] with the path to your SQLite database file
    database_file = "/opt/airflow/working_data/noaa_goes_date.db"
    # Set up the GCS client
    creds = Credentials.from_service_account_file("/opt/airflow/sa.json")
    client = storage.Client(credentials=creds, project=creds.project_id)
    bucket = client.bucket(bucket_name)
    blob = bucket.blob("noaa_goes_date.db")
    if blob.exists():
        print("Database file already exists in GCS. Updating tables...")
        # Code to update the tables in the existing database file goes here
        temp_file = "/opt/airflow/working_data/noaa_goes_date.db"
        with open(temp_file, "wb") as f:
            blob.download_to_file(f)

        conn = sqlite3.connect(temp_file)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS noaa_nexrad_level2_date")
        # Create a new table
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS noaa_nexrad_level2_date (year text, month text, day text, station text)"
        )
        for data in year_month_day_station_code:
            year, month, day, station = data
            cursor.execute(
                "INSERT INTO noaa_nexrad_level2_date VALUES (?, ?, ?, ?)",
                (year, month, day, station),
            )
        conn.commit()
        conn.close()

        # Upload the updated database file to GCS
        with open(temp_file, "rb") as f:
            blob.upload_from_file(f)

    else:
        print("Uploading database file to GCS...")

        conn = sqlite3.connect(database_file)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS noaa_nexrad_level2_date")
        # Create a new table
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS noaa_nexrad_level2_date (year text, month text, day text, station text)"
        )
        for data in year_month_day_station_code:
            year, month, day, station = data
            cursor.execute(
                "INSERT INTO noaa_nexrad_level2_date VALUES (?, ?, ?, ?)",
                (year, month, day, station),
            )
        conn.commit()
        conn.close()

        blob.upload_from_filename(database_file)


run_this = PythonOperator(
    task_id="nexrad_ETL",
    python_callable=nexrad_ETL,
    dag=dag,
)
