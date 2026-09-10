FROM python:3.13-alpine
WORKDIR /app
COPY manager.py ./
EXPOSE 8080
ENTRYPOINT ["python", "/app/manager.py"]
