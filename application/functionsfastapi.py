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
