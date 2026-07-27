FROM python:3.13.14-alpine

RUN addgroup -g 9000 app \
    && adduser -D -u 9000 -G app app

WORKDIR /app
COPY requirements.txt requirements.txt

RUN apk add --no-cache pango fontconfig ttf-freefont \
    && pip3 install -r requirements.txt

COPY --chown=app:app . .
USER app

CMD ["gunicorn", "--workers", "4", "--timeout", "90", "--bind", "127.0.0.1:8000", "wsgi:app"]

HEALTHCHECK --interval=30s --timeout=30s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1
