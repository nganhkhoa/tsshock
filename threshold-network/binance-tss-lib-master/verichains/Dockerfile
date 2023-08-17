FROM python:3
ADD ./scripts /scripts
RUN pip install -r /scripts/requirements.txt 
EXPOSE 1337
CMD python3 /scripts/app.py