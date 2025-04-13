FROM golang:1.24.2-alpine3.21 AS build_deps
RUN apk add --no-cache 'git' 'libssl3' 'libcrypto3'
WORKDIR /app
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
RUN go mod download
FROM build_deps AS build
COPY . .
RUN CGO_ENABLED=0 go build -o auth_configserver_ldap -ldflags '-w -extldflags "-static"' .
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /app/auth_configserver_ldap /usr/local/bin/auth_configserver_ldap
ENTRYPOINT ["auth_configserver_ldap"]
CMD []
USER 1080:1080
EXPOSE 8080
