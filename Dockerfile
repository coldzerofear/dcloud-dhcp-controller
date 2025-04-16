FROM quay.io/jitesoft/ubuntu:22.04 as builder

ARG TARGETARCH=amd64
ARG TARGETOS=linux

# use golang version
ARG GOLANG_VERSION=1.22.3

RUN echo "Asia/Shanghai" > /etc/timezone && \
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
# install compilation environment
RUN apt-get update && apt-get install -y --no-install-recommends g++ ca-certificates wget dpdk dpdk-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

# downlown golang
RUN wget -nv -O - https://golang.google.cn/dl/go${GOLANG_VERSION}.${TARGETOS}-${TARGETARCH}.tar.gz \
    | tar -C /usr/local -xz

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,direct

WORKDIR /go/src/dcloud-dhcp-controller

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY main.go main.go
COPY pkg/  pkg/

RUN CGO_ENABLED=1 GOOS=${TARGETOS:-linux} \
	CGO_CFLAGS_ALLOW="-mrtm|-Wp,-D_FORTIFY_SOURCE.*|-fstack-protector.*" \
 	CGO_LDFLAGS_ALLOW="-Wl,--(?:no-)?whole-archive|-Wl,-z,now|-Wl,-z,relro" \
    go build -ldflags="-extldflags=-Wl,--no-as-needed" -o dhcp-controller .


FROM quay.io/jitesoft/ubuntu:22.04

RUN echo "Asia/Shanghai" > /etc/timezone && \
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
# install runtime environment
RUN apt-get update && apt-get install -y dpdk dpdk-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/src/dcloud-dhcp-controller/dhcp-controller /app/

WORKDIR /app

ENTRYPOINT ["./dhcp-controller"]