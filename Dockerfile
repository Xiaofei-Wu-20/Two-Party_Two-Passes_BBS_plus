FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /project

RUN apt-get clean \ && apt-get -y update && apt-get -y install \
    software-properties-common \
    wget \
    build-essential \
    libssl-dev \
    libgmp-dev \
    && echo "/usr/lib/x86_64-linux-gnu" >> /etc/ld.so.conf.d/local.conf \
    && ldconfig


RUN cd /opt && wget https://github.com/Kitware/CMake/releases/download/v3.29.6/cmake-3.29.6.tar.gz \
    && tar -zxvf cmake-3.29.6.tar.gz \
    &&  cd cmake-3.29.6 \
    && ./bootstrap \
    && make -j$(nproc) && make install \
    && rm ../cmake-3.29.6.tar.gz

COPY ./build.sh /

ENV DOCKER=on

CMD ["bash", "/build.sh"]