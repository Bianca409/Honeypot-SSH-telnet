FROM python:3.12-slim

# Creem un utilizator non-root pentru securitate
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Instalam dependentele
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiem codul sursa
COPY . .

# Setam permisiunile pentru userul non-root
USER appuser

CMD ["python", "-m", "uvicorn", "src.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
