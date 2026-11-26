# syntax=docker/dockerfile:1

# --- build ---
FROM golang:1.22-alpine AS build

WORKDIR /src

# Dependencies first for better layer caching. There are none outside stdlib,
# but the module files still need to exist.
COPY go.mod ./
RUN go mod download

COPY . .

# CGO off keeps the binary static, so the runtime stage can be scratch-like and
# has no shell, no package manager, and no libc for an attacker to work with.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w -buildid=" -o /out/otss ./cmd/otss

# --- runtime ---
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/otss /otss

# Unprivileged user, read-only filesystem at runtime (enforced in compose).
USER nonroot:nonroot
EXPOSE 8080

# No shell in this image: HEALTHCHECK has to be a direct exec.
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=3 \
  CMD ["/otss", "-healthcheck"]

ENTRYPOINT ["/otss"]
