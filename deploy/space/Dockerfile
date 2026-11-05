# Hugging Face Docker Space: Streamlit only, simulated models, nothing a visitor can repoint.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app LLM_PROVIDER=mock QUARANTINE_PROVIDER=mock PUBLIC_DEMO=true DB_PATH=/tmp/alertlens.db HOME=/tmp
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -m data.generator.generate --seed 42 --n 2000 --out data/benchmark \
 && python -m alertlens.scoring.model \
 && python -m alertlens.safety.classifier \
 && chmod -R a+rX /app && chmod -R a+rwX /app/models
EXPOSE 7860
CMD ["sh", "-c", "python -m scripts.seed_db; exec streamlit run ui/Home.py --server.address 0.0.0.0 --server.port 7860 --server.enableXsrfProtection false --server.enableCORS false"]
