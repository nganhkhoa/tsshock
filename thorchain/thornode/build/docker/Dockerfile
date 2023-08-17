#
# THORChain
#

#
# Build
#
FROM registry.gitlab.com/thorchain/thornode:builder-v3@sha256:cd8a5f569e8978e7fdedb85039ddac3cf19cb5831c4823e9635b69c2b1ff6957 AS build

ENV GOBIN=/go/bin
ENV GOPATH=/go
ENV CGO_ENABLED=0
ENV GOOS=linux

WORKDIR /app
COPY go.mod go.sum ./
COPY ./pkg ./pkg
RUN go mod download

COPY . .

ARG TAG=mainnet
RUN make install

#
# Main
#
FROM registry.gitlab.com/thorchain/thornode:runner-base-v1@sha256:8fc433efa3e853b59cafe920654705e37c94228ae99cba6892933a61594c11f3

# Copy the compiled binaries over.
COPY --from=build /go/bin/generate /go/bin/thornode /go/bin/bifrost /usr/bin/

COPY build/scripts /scripts

# default to mainnet
ARG TAG=mainnet
ENV NET=$TAG

# default to fullnode
CMD ["/scripts/fullnode.sh"]
