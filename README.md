[![Continuous Integration - FastAPI](https://github.com/BigDataIA-Spring2023-Team-04/Assignment-2/actions/workflows/fastapi.yml/badge.svg?branch=lokesh)](https://github.com/BigDataIA-Spring2023-Team-04/Assignment-2/actions/workflows/fastapi.yml)
[![Continuous Integration - UnitTesting](https://github.com/BigDataIA-Spring2023-Team-04/Assignment-2/actions/workflows/pytest.yml/badge.svg?branch=lokesh)](https://github.com/BigDataIA-Spring2023-Team-04/Assignment-2/actions/workflows/pytest.yml)
----------------------------------
## Team Information and Contribution 

Name | NUID | Contribution 
--- | --- | --- |
Karan Agrawal | 001090008 | 25% 
Rishabh Singh | 002743830 | 25% 
Lokeshwaran Venugopal Balamurugan | 002990533 | 25% 
Sivaranjani S | 002742197 | 25% 


# Link to Live Applications
- Streamlit Application - http://34.138.127.169:8000
- FAST API Swagger - http://34.138.127.169:8090/docs
- Airflow - http://34.138.127.169:8080
- Codelabs - https://codelabs-preview.appspot.com/?file_id=1gsAswrJAOnjFcGvwVnXr3FeQ8RwgIqtXCtZhtMJpajI#1

# Project Tree
```
📦 
├─ .DS_Store
├─ .github
│  ├─ .DS_Store
│  └─ workflows
│     ├─ fastapi.yml
│     └─ pytest.yml
├─ .gitignore
├─ Airflow
│  ├─ dags
│  │  ├─ geos-etl.py <- GEOS ETL DAG
│  │  └─ nexrad-etl.py <- NEXTRAD ETL DAG
│  └─ docker-compose.yaml
├─ Dockerfile
├─ README.md
├─ application
│  ├─ .DS_Store
│  ├─ Dockerfile
│  ├─ __init__.py
│  ├─ database.py <- Database Setup for FASTAPI
│  ├─ functionsfastapi.py <- Helper Functions for FASTAPI
│  ├─ gcp_bucket_connect.py <- Connect to Database in Google Cloud Storage
│  ├─ hashing.py <- Helper Function to Hash Passwords
│  ├─ main1.py <- Main FASTAPI Function
│  ├─ main_test.py <- Test Cases for FASTAPI
│  ├─ models.py <- Models for Tables in Database
│  ├─ nexrad-stations.csv
│  ├─ req.txt 
│  ├─ schema.py <- Schema Model for Tables in Database
│  ├─ test_main1.py
│  └─ users.db
├─ arch-diag
│  ├─ arch.py <- Code to Create Architechture Diagram
│  └─ deployment_architecture_diagram.png <- Deployment Architechture
├─ dashboard
│  ├─ .DS_Store
│  ├─ geos.py <- Dashboard for GEOS
│  ├─ nextrad.py <- Dashboard for NEXTRAD
│  └─ nextrad_stations.py <- Dashboard for NEXTRAD Stations
├─ docker-compose.yml
├─ great_expectations
│  ├─ expectations
│  │  ├─ .ge_store_backend_id
│  │  ├─ geos_suite.json
│  │  └─ nextrad_suite.json
│  ├─ great_expectations.yml
│  ├─ plugins
│  │  └─ custom_data_docs
│  │     └─ styles
│  │        └─ data_docs_custom_styles.css
│  └─ uncommitted
│     ├─ config_variables.yml
│     ├─ data_docs
│     │  └─ local_site
│     │     ├─ expectations
│     │     │  ├─ geos_suite.html
│     │     │  └─ nextrad_suite.html
│     │     ├─ index.html
│     │     ├─ static
│     │     │  ├─ fonts
│     │     │  │  └─ HKGrotesk
│     │     │  │     ├─ HKGrotesk-Bold.otf
│     │     │  │     ├─ HKGrotesk-BoldItalic.otf
│     │     │  │     ├─ HKGrotesk-Italic.otf
│     │     │  │     ├─ HKGrotesk-Light.otf
│     │     │  │     ├─ HKGrotesk-LightItalic.otf
│     │     │  │     ├─ HKGrotesk-Medium.otf
│     │     │  │     ├─ HKGrotesk-MediumItalic.otf
│     │     │  │     ├─ HKGrotesk-Regular.otf
│     │     │  │     ├─ HKGrotesk-SemiBold.otf
│     │     │  │     └─ HKGrotesk-SemiBoldItalic.otf
│     │     │  ├─ images
│     │     │  │  ├─ favicon.ico
│     │     │  │  ├─ glossary_scroller.gif
│     │     │  │  ├─ iterative-dev-loop.png
│     │     │  │  ├─ logo-long-vector.svg
│     │     │  │  ├─ logo-long.png
│     │     │  │  ├─ short-logo-vector.svg
│     │     │  │  ├─ short-logo.png
│     │     │  │  └─ validation_failed_unexpected_values.gif
│     │     │  └─ styles
│     │     │     ├─ data_docs_custom_styles_template.css
│     │     │     └─ data_docs_default_styles.css
│     │     └─ validations
│     │        ├─ geos_suite
│     │        │  └─ __none__
│     │        │     └─ 20230208T123514.819212Z
│     │        │        └─ c59c2bdb213b5f9e335d32dae79e3ecb.html
│     │        └─ nextrad_suite
│     │           └─ __none__
│     │              ├─ 20230208T124414.909973Z
│     │              │  └─ 3569fdb9ee9f77966268f4060430f226.html
│     │              └─ 20230208T124447.357538Z
│     │                 └─ 3569fdb9ee9f77966268f4060430f226.html
│     ├─ datasource_new.ipynb
│     ├─ edit_geos_suite.ipynb
│     ├─ edit_nextrad_suite.ipynb
│     └─ validations
│        ├─ .ge_store_backend_id
│        ├─ geos_suite
│        │  └─ __none__
│        │     └─ 20230208T123514.819212Z
│        │        └─ c59c2bdb213b5f9e335d32dae79e3ecb.json
│        └─ nextrad_suite
│           └─ __none__
│              ├─ 20230208T124414.909973Z
│              │  └─ 3569fdb9ee9f77966268f4060430f226.json
│              └─ 20230208T124447.357538Z
│                 └─ 3569fdb9ee9f77966268f4060430f226.json
├─ main.py
├─ requirements.txt
├─ signin.py
└─ test.py
```
©generated by [Project Tree Generator](https://woochanleee.github.io/project-tree-generator)

# API Endpoint Description
 - /get_goes_url (POST): Given a filename, the endpoint generates the S3 URL for the corresponding file hosted on the GOES-18 S3 bucket. If the file is not found, an HTTP 404 error is returned. This endpoint also checks for the file format and raises an HTTP 400 error if the format is incorrect.

- /get_nexrad_url (POST): Given a filename, the endpoint generates the S3 URL for the corresponding file hosted on the NEXRAD level 2 S3 bucket. If the file is not found, an HTTP 404 error is returned. This endpoint also checks for the file format and raises an HTTP 400 error if the format is incorrect.

- /get_goes_url_parameters (POST): Given the year, day of year, and hour of a GOES-18 satellite file, the endpoint generates a list of URLs for all files matching the specified parameters. This endpoint returns an HTTP 404 error if the directory specified by the parameters is not found.

- /get_nexrad_url_parameters (POST): Given the year, month, day, and station ID of a NEXRAD level 2 file, the endpoint generates a list of URLs for all files matching the specified parameters. This endpoint returns an HTTP 404 error if the directory specified by the parameters is not found.

- /get_unique_years_geos (GET): Returns a list of all unique years for which GOES-18 satellite files are available in the database.

- /get_unique_days_geos (GET): Given a year, returns a list of all unique days of the year for which GOES-18 satellite files are available in the database.

- /get_unique_hours_geos (GET): Given a year and day of year, returns a list of all unique hours of the day for which GOES-18 satellite files are available in the database.

- /get_file_names_geos (GET): Given a year, day of year, and hour, returns a list of all file names matching the specified parameters for the GOES-18 satellite.

- /get_unique_years_nexrad (GET): Returns a list of all unique years for which NEXRAD level 2 files are available in the database.

- /get_unique_months_nexrad (GET): Given a year, returns a list of all unique months of the year for which NEXRAD level 2 files are available in the database.

- /get_unique_days_nexrad (GET): Given a year and month, returns a list of all unique days of the month for which NEXRAD level 2 files are available in the database.

- /get_unique_stations_nexrad (GET): Given a year, month, and day, returns a list of all unique station IDs for which NEXRAD level 2 files are available in the database.

- /get_file_names_nexrad (GET): Given a year, month, day, and station ID, returns a list of all file names matching the specified parameters for the NEXRAD level 2 files.

- /download_and_upload_s3_file (POST): Downloads a file from a specified S3 bucket and uploads it to another specified S3 bucket. If the file already exists in the destination bucket, the function returns a download URL for the existing file. Otherwise, it uploads the file and returns
