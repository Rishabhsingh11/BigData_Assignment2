import os

import boto3
from botocore.exceptions import ClientError
from fastapi import Body, Depends, FastAPI, HTTPException, status

app = FastAPI()

AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")

s3_client = boto3.client(
    "s3",
    region_name="us-east-1",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
)


###########################################################################################################################################
## User API Endpoints
###########################################################################################################################################
@app.post("/get_goes_url", status_code=200, tags=["GEOS"])
async def get_goes_url_by_filename(
    file_name: str = Body(...),
):
    if file_name.endswith(".gz"):
        raise HTTPException(
            status_code=400,
            detail="Incorrect file format (the .gz file format is not supported).",
        )
    else:
        file_name = file_name.split("=")[-1]
        # Split the file name into parts
        parts = file_name.split("_")
        # Extract relevant information from the file name
        name = "-".join(parts[1].split("-")[:3])
        if name[-1].isdigit():
            name = name[:-1]
        year = parts[3][1:5]
        day_of_year = parts[3][5:8]
        hour = parts[3][8:10]
        # Generate URL for file on NOAA GOES-18 satellite AWS S3 bucket
        url = f"https://noaa-goes18.s3.amazonaws.com/ABI-L1b-RadC/{year}/{day_of_year}/{hour}/{file_name}"
        if search_file_goes(file_name, s3_client):
            return {"file_url": url}
        else:
            raise HTTPException(
                status_code=404, detail="File not found in the GEOS-18 S3 bucket."
            )


@app.post("/get_nexrad_url", status_code=200, tags=["NEXTRAD"])
def get_nexrad_url_by_filename(
    file_name: str = Body(...),
):
    print(file_name)
    if file_name.endswith(".nc"):
        raise HTTPException(
            status_code=400,
            detail="Incorrect file format (the .nc file format is not supported).",
        )
    else:
        file_name = file_name.split("=")[-1]
        # Split the file name into parts
        parts = file_name.split("_")
        # Extract relevant information from the file name
        station = parts[0][0:4]
        year = parts[0][4:8]
        month = parts[0][8:10]
        day = parts[0][10:12]
        # Generate URL for file on NEXRAD level 2 AWS S3 bucket
        url = f"https://noaa-nexrad-level2.s3.amazonaws.com/{year}/{month}/{day}/{station}/{file_name}"
        if search_file_nexrad(file_name, s3_client):
            return {"file_url": url}
        else:
            raise HTTPException(
                status_code=404, detail="File not found in the NEXRAD S3 bucket."
            )


@app.post("/get_goes_url_parameters", status_code=200, tags=["GEOS"])
def get_goes_url_by_parameters(
    year: str = Body(...),
    day_of_year: str = Body(...),
    hour: str = Body(...),
):
    if year not in ["2022", "2023"]:
        raise HTTPException(status_code=400, detail="Year must be 2022 or 2023")
    if year == "2022" and not (209 <= int(day_of_year) <= 365):
        raise HTTPException(
            status_code=400,
            detail="Day of year must be between 209 and 365 for year 2022",
        )
    if year == "2023" and not (1 <= int(day_of_year) <= 365):
        raise HTTPException(
            status_code=400,
            detail="Day of year must be between 1 and 365 for year 2023",
        )
    if not (0 <= int(hour) <= 23):
        raise HTTPException(status_code=400, detail="Hour must be between 00 and 23")

    bucket_name = "noaa-goes18"
    directory_path = f"ABI-L1b-RadC/{year}/{day_of_year}/{hour}/"
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=directory_path)
        files = [content["Key"] for content in response["Contents"]]
    except KeyError:
        # Return 404 error if directory is not found
        raise HTTPException(status_code=404, detail="Invalid directory")
    except ClientError:
        # Return 500 error if there is an S3 client error
        raise HTTPException(status_code=500, detail="Internal server error")

    # Return list of file URLs as JSON response
    # urls = [f"https://{bucket_name}.s3.amazonaws.com/{file}" for file in files]
    return {"file_urls": files}


@app.post("/get_nexrad_url_parameters", status_code=200, tags=["NEXTRAD"])
def get_nexrad_url_by_parameters(
    year: str = Body(...),
    month: str = Body(...),
    day: str = Body(...),
    Station: str = Body(...),
):
    bucket_name = "noaa-nexrad-level2"
    directory_path = f"{year}/{month}/{day}/{Station}/"
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=directory_path)
        files = [content["Key"] for content in response["Contents"]]
    except KeyError:
        # Return 404 error if directory is not found
        raise HTTPException(status_code=404, detail="Invalid Directory")
    except ClientError:
        # Return 500 error if there is an S3 client error
        raise HTTPException(status_code=500, detail="Internal server error")

    # Return list of file URLs as JSON response
    urls = [f"https://{bucket_name}.s3.amazonaws.com/{file}" for file in files]
    return {"file_urls": urls}


@app.get("/get_file_names_geos", status_code=200, tags=["GEOS"])
async def get_file_names():
    bucket_name = "noaa-goes18"
    directory_path = f"ABI-L1b-RadC/2022/214/09/"
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=directory_path)
        files = [
            content["Key"].split("/")[-1] for content in response.get("Contents", [])
        ]
    except KeyError:
        # Return 404 error if directory is not found
        raise HTTPException(status_code=404, detail="Invalid directory")
    except ClientError:
        # Return 500 error if there is an S3 client error
        raise HTTPException(status_code=500, detail="Internal server error")
    return {"files": files}


@app.get("/get_file_names_nexrad", status_code=200, tags=["NEXTRAD"])
async def get_file_names():
    bucket_name = "noaa-nexrad-level2"
    directory_path = f"2022/10/10/KJGX/"
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=directory_path)
        files = [
            content["Key"].split("/")[-1] for content in response.get("Contents", [])
        ]
    except KeyError:
        # Return 404 error if directory is not found
        raise HTTPException(status_code=404, detail="Invalid directory")
    except ClientError:
        # Return 500 error if there is an S3 client error
        raise HTTPException(status_code=500, detail="Internal server error")
    return {"files": files}


def search_file_goes(file_name, s3):
    file_name = get_link_goes(file_name)
    try:
        s3.head_object(Bucket="noaa-goes18", Key=file_name)
        return True
    except:
        return False


def search_file_nexrad(file_name, s3_client):
    file_name = get_link_nexrad(file_name)
    try:
        s3_client.head_object(Bucket="noaa-nexrad-level2", Key=file_name)
        return True
    except:
        return False


def get_link_goes(file_name):
    parts = file_name.split("_")
    name = "-".join(parts[1].split("-")[:3])
    if name[-1].isdigit():
        name = name[: len(name) - 1]
    year = parts[3][1:5]
    day_of_year = parts[3][5:8]
    hour = parts[3][8:10]
    url = f"ABI-L1b-RadC/{year}/{day_of_year}/{hour}/{file_name}"
    return url


def get_link_nexrad(file_name):
    parts = file_name.split("_")
    station = parts[0][0:4]
    year = parts[0][4:8]
    month = parts[0][8:10]
    day = parts[0][10:12]
    url = f"{year}/{month}/{day}/{station}/{file_name}"
    return url
