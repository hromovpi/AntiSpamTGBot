FROM python:3.12-slim
WORKDIR /app
RUN useradd --uid 10001 --create-home bot && mkdir /app/data && chown bot:bot /app/data
COPY bot.py .
USER bot
CMD ["python", "-u", "bot.py"]
