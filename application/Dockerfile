FROM python:3.10.6

RUN pip install --upgrade pip

WORKDIR /app

ADD main1.py req.txt functionsfastapi.py database.py hashing.py models.py schema.py gcp_bucket_connect.py /app/

RUN pip install -r req.txt

ADD functionsfastapi.py /app/

ADD nexrad-stations.csv /app/

ADD users.db /app/

EXPOSE 8000
# Expose a port inside the container on which services run

CMD ["gunicorn" ,"-w", "4", "-k", "uvicorn.workers.UvicornWorker" , "--bind", "0.0.0.0:8000", "main1:app"]