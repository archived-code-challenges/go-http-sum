FROM golang:1.18 as builder
RUN go version

WORKDIR /app
COPY . /app

RUN [ -d bin ] || mkdir bin
RUN GOOS=linux CGO_ENABLED=0 go build -o bin/server .

ENTRYPOINT /app/bin/server
