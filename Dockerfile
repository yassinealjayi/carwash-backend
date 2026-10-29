FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY main_vps.py ./main_vps.py
RUN useradd --system --uid 10001 carwash && mkdir -p /data && chown carwash:carwash /data
USER carwash
EXPOSE 8000
CMD ["uvicorn","main_vps:app","--host","0.0.0.0","--port","8000","--proxy-headers","--forwarded-allow-ips","*"]
