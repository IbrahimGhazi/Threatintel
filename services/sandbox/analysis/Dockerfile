FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        strace tcpdump inotify-tools libfaketime \
        python3 python3-pip perl ruby \
        curl wget net-tools iproute2 procps \
        file binutils xdotool \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m analyst
WORKDIR /
CMD ["sleep", "infinity"]
