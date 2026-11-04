FROM python:3.12-slim
WORKDIR /srv/trustvault
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /srv/trustvault/data /srv/trustvault/private_storage
ENV DATABASE_PATH=/srv/trustvault/data/trustvault.db
ENV STORAGE_PATH=/srv/trustvault/private_storage
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
