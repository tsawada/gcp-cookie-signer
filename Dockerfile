FROM golang:1.19 as builder

WORKDIR /go/src
COPY go.mod go.sum ./
RUN go mod download

COPY ./main.go ./
ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64
RUN go build -ldflags="-s -w -extldflags \"-static\"" -o /go/bin/gcp-cookie-signer main.go

FROM scratch
COPY --from=build /go/bin/gcp-cookie-signer /usr/bin/gcp-cookie-signer

ENTRYPOINT ["/usr/bin/gcp-cookie-signer"]
