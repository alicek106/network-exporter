# docker build . -t alicek106/network-exporter:0.0
FROM alicek106/ebpf-base-image:1.0.0 
RUN mkdir /app
ADD . /app
WORKDIR /app
CMD ["/app/app"]
