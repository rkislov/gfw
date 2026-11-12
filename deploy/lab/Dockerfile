FROM alt:p10
RUN apt-get update && apt-get install -y nftables iproute2 python3 curl && apt-get clean
RUN apt-get install -y etcnet && apt-get clean
WORKDIR /work
