# Base image olarak python:3.9 kullanıyoruz
FROM python:3.9-slim

# Sistem bağımlılıklarını yükle
RUN apt-get update && apt-get install -y gcc

# Çalışma dizinini oluştur ve ayarla
WORKDIR /app

# Gerekli dosyaları kopyala
COPY requirements.txt requirements.txt
COPY app.py app.py
COPY update_mikrotik.py update_mikrotik.py
COPY templates/ templates/
COPY .env .env

# Bağımlılıkları yükle
RUN pip install --no-cache-dir -r requirements.txt

# Veritabanı dizinini oluştur ve izinleri ayarla
RUN mkdir -p /app/data && chmod -R 777 /app/data

# Gunicorn ile Flask uygulamasını başlat
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
