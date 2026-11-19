FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /web
COPY src/frontend/package.json src/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY src/frontend/ ./
ARG VITE_OIDC_AUTHORITY=http://localhost:8081/realms/temporalmark
ENV VITE_OIDC_AUTHORITY=$VITE_OIDC_AUTHORITY
RUN npm run build

FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10
COPY docker/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY docker/nginx-privacy-logs.conf /etc/nginx/conf.d/00-temporalmark-log-format.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 80
