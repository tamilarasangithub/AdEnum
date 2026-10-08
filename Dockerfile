FROM python:3.11-slim

WORKDIR /app

# System deps needed by impacket / ldap3 (kerberos headers, build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libkrb5-dev krb5-user \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

EXPOSE 8080

CMD ["adenum", "serve", "--port", "8080"]
