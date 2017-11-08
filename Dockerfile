FROM golang:1.9.2-alpine AS builder
WORKDIR $GOPATH/src/github.com/travelaudience/kubernetes-vault-client
COPY . .
RUN CGO_ENABLED=0 go build -a -installsuffix cgo -o /kubernetes-vault-client -v ./main.go

FROM alpine:3.6
COPY --from=builder /kubernetes-vault-client /usr/local/bin/
RUN apk add --no-cache ca-certificates
CMD ["kubernetes-vault-client"]
