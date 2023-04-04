FROM continuumio/miniconda3

WORKDIR /code

RUN conda install -c conda-forge mysqlclient

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . /code