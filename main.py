def get_url_geos(file_name):
    try:
        parts = file_name.split("_")
        name = "-".join(parts[1].split("-")[:3])
        if name[-1].isdigit():
            name = name[: len(name) - 1]
        year = parts[3][1:5]
        day_of_year = parts[3][5:8]
        hour = parts[3][8:10]
        url = f"https://noaa-goes18.s3.amazonaws.com/{name}/{year}/{day_of_year}/{hour}/{file_name}"
        return url
    except:
        return ""


def get_url_nextrad(file_name):
    try:
        parts = file_name.split("_")
        station = parts[0][0:4]
        year = parts[0][4:8]
        month = parts[0][8:10]
        day = parts[0][10:12]
        url = f"https://noaa-nexrad-level2.s3.amazonaws.com/{year}/{month}/{day}/{station}/{file_name}"
        return url
    except Exception as e:
        pass


print(
    f"Calling the get_url_geos function: {get_url_geos('OR_ABI-L1b-RadC-M6C01_G18_s20230050416177_e20230050418555_c20230050418597.nc')}"
)
print(
    f"Calling the get_url_nextrad function: {get_url_nextrad('KAKQ20050101_000354.gz')}"
)
