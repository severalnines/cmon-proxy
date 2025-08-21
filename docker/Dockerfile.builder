FROM golang:1.25-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
      cmake \
      g++ \
      rpm && \
    apt-get clean


