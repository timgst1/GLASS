# ---- build ----
FROM golang:1.25.4-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/glass ./cmd/glass

# ---- run ----
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/glass /glass
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/glass"]
