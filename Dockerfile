FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY setup_sandbox.sh .

# This RUN happens during the image BUILD, where we are root, so we're
# allowed to create directories under /srv. (At container *start* time,
# Render runs the process as a non-root user, which is what caused the
# "Permission denied" you saw.)
RUN chmod +x setup_sandbox.sh && bash setup_sandbox.sh \
    && chmod -R a+rX /srv/agent-redteam

EXPOSE 8000

CMD uvicorn main:app --host 0.0.0.0 --port $PORT
