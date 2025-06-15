FROM python:latest

WORKDIR /app
COPY password_vault.py .

RUN apt-get update && apt-get install -y tk

RUN pip install --no-cache-dir pyperclip cryptography

CMD ["python", "password_vault.py"]