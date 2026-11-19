FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY faultline_addon.py .
COPY faults/ faults/
EXPOSE 8080
ENV SCENARIO=faults/baseline.yaml TAPE=/data/tape.jsonl
CMD ["sh", "-c", "mitmdump --listen-port 8080 --set block_global=false -s faultline_addon.py --set scenario=$SCENARIO --set tape=$TAPE"]
