FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10002 proxyuser
WORKDIR /app
COPY --chown=proxyuser:proxyuser egress_proxy.py /app/egress_proxy.py
USER 10002:10002
EXPOSE 3128
CMD ["python", "/app/egress_proxy.py"]
