FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gateway .

FROM scratch
COPY --from=build /gateway /gateway
USER 65532:65532
EXPOSE 8443 8080
ENTRYPOINT ["/gateway"]
