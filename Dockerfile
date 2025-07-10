FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN apt-get update && apt-get install -y cron awscli nano
COPY backup.sh /app/backup.sh
RUN chmod +x /app/backup.sh
RUN (crontab -l 2>/dev/null; echo "0 */2 * * * /app/backup.sh >> /var/log/cron.log 2>&1") | crontab -

EXPOSE 5001

CMD cron && flask run --host=0.0.0.0 --port=5001