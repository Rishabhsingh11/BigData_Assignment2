FROM python:3.10.6

RUN pip install --upgrade pip

WORKDIR /app

ADD signin.py requirements.txt /app/

RUN pip install -r requirements.txt

ADD dashboard /app/dashboard/
ADD dashboard/geos.py /app/dashboard/
ADD dashboard/nextrad.py /app/dashboard/
ADD dashboard/nextrad_stations.py /app/dashboard/

EXPOSE 8080

CMD ["streamlit", "run", "signin.py", "--server.port", "8080"]