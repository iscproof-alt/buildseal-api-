FROM node:18-slim

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    curl build-essential pkg-config libssl-dev openssl \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN python3 -m venv /venv && \
    /venv/bin/pip install reportlab

# Binary pre-built and committed as isc_pack_v5_bin

ENV PATH="/venv/bin:${PATH}"

EXPOSE 3000
CMD ["node", "index.js"]
