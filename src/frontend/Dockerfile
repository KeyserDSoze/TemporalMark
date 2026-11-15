FROM node:22-alpine AS build
WORKDIR /web
COPY src/frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY src/frontend/ ./
ARG VITE_OIDC_AUTHORITY=http://localhost:8081/realms/temporalmark
ENV VITE_OIDC_AUTHORITY=$VITE_OIDC_AUTHORITY
RUN npm run build

FROM nginx:1.27-alpine
COPY docker/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 80
