FROM python:3.13-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bootstrap.py .
COPY rfp_extension.py .
COPY admin_boundary.py .
COPY multi_app_extension.py .
COPY b2b_oidc_extension.py .
CMD ["sh", "-c", "python -u bootstrap.py && python -u rfp_extension.py && python -u admin_boundary.py && python -u multi_app_extension.py && python -u b2b_oidc_extension.py"]
