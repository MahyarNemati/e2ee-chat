# Build the relay and the client as one static binary.
FROM golang:1.27-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=docker
# CGO is off for the build only -- the race detector in CI needs it on.
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/e2ee-chat ./cmd/e2ee-chat

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/e2ee-chat /usr/local/bin/e2ee-chat
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/e2ee-chat"]
CMD ["serve", "-addr", ":8080"]
