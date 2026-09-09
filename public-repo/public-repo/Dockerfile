FROM python:3.11-slim

# python:3.11-slim's own Debian base layer can lag behind Debian's security
# repo between upstream rebuilds -- confirmed live: the image-scan gate
# blocking today's dev deploy flagged 9 HIGH CVEs (led by CVE-2026-53615)
# in bsdutils/util-linux/login, all fixed upstream but not yet present in
# whatever base layer was last pulled. These are real base-OS packages this
# image genuinely needs (unlike e.g. a runtime-only Node image's bundled
# npm/npx), so the fix is upgrading them in place, not stripping them.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
