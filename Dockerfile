
ARG GO_VERSION=1.12

FROM golang:${GO_VERSION}-alpine AS builder

RUN adduser -h /user -D -s "" user 

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./main.go ./

RUN CGO_ENABLED=0 go build -installsuffix 'static' -o /app .

FROM scratch AS final
COPY --from=builder /etc/group /etc/passwd /etc/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs
COPY --from=builder /app /app

EXPOSE 8080 8443

USER user:user

ENTRYPOINT ["/app". ":8080", ":8443", "/wwwroot"]

