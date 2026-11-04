FROM python:3.12-slim
WORKDIR /app
ENV PYTHONPATH=/app LLM_PROVIDER=mock DB_PATH=/data/alertlens.db
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python -m data.generator.generate --seed 42 --n 2000 --out data/benchmark \
 && python -m alertlens.scoring.model
EXPOSE 8000 8501
CMD ["sh", "-c", "python -m scripts.seed_db && uvicorn alertlens.api.main:app --host 0.0.0.0 --port 8000 --log-level warning & streamlit run ui/Home.py --server.address 0.0.0.0"]
