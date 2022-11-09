# syntax=docker/dockerfile:1

FROM python:3.10
WORKDIR /ssl_monitor/

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY . /ssl_monitor/

RUN apt update 
RUN pip install -r requirements.txt