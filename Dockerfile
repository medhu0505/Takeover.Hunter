FROM python:3.13

# Install Go
RUN curl -sL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master

ENV PATH="${PATH}:/root/go/bin"

# Copy app
COPY . .

# Run
CMD ["python", "app.py"]
