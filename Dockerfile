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

RUN cd isc_pack_v5 && cargo build --release && cp target/release/isc_pack_v5 /app/isc_pack_v5_bin

ENV PATH="/venv/bin:${PATH}"

# FreeTSA sertifikalarını indir
RUN curl -s https://freetsa.org/files/cacert.pem -o /tmp/freetsa_ca.pem &&     curl -s https://freetsa.org/files/tsa.crt -o /tmp/freetsa_tsa.crt

EXPOSE 3000
CMD ["node", "index.js"]
