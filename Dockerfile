FROM python:3.7-alpine3.11 AS build-image

RUN addgroup -S runner && adduser -S runner -G runner

USER runner

WORKDIR /home/runner/

COPY requirements.txt .
RUN pip install --user -r requirements.txt

COPY run.py .

ENTRYPOINT [ "python" ]
CMD ["run.py"]