import sqlite3
import tempfile

from google.cloud import storage
from google.oauth2 import service_account


def get_sqlite_connection():
    # Authenticate the application with GCP
    json_file_path = "/fastapi/key.json"
    credentials = service_account.Credentials.from_service_account_file(
        json_file_path, scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )

    # Create a client for the GCS bucket
    client = storage.Client(credentials=credentials)

    # Get a reference to the GCS bucket
    bucket = client.bucket("db_bucket_damg7245")

    # Get a reference to the database file in the GCS bucket
    blob = bucket.blob("noaa_goes_date.db")

    # Download the database file from the GCS bucket into memory as a bytes object
    db_file = blob.download_as_string()

    # Create a temporary file for the database file
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(db_file)
    temp_file.close()

    # Connect to the temporary file as if it were a database file
    conn = sqlite3.connect(temp_file.name)

    # Return the connection
    return conn
