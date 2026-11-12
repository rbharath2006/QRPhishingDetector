FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10003 gatewayuser
WORKDIR /app
COPY --chown=gatewayuser:gatewayuser gateway.py /app/gateway.py
USER gatewayuser
EXPOSE 8765
CMD ["python", "/app/gateway.py"]
