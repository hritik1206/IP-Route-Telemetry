FROM python:latest
RUN pip install flask
RUN pip install redis
RUN pip install waitress
RUN pip install flask_cors
COPY pri.py .
CMD ["python3","pri.py"]
