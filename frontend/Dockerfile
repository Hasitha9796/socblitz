# ── Build stage ───────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

ARG VITE_API_URL=https://localhost
ENV VITE_API_URL=$VITE_API_URL

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

# ── Production stage ───────────────────────────────────────────────────────────
FROM nginx:1.27-alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Auto-generate self-signed TLS cert if not mounted
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/certs/key.pem \
        -out /etc/nginx/certs/cert.pem \
        -subj "/C=US/ST=State/L=City/O=SocBlitz/CN=localhost"

EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
