#!/bin/bash

DOCKER_IMAGE_NAME="threshold_ecdsa_builder"

if [ $DOCKER ];then
	cd /project
	rm -rf ./build
	mkdir build && cd build
  cmake ..
  make -j$(nproc)

else
  sudo docker build -t "$DOCKER_IMAGE_NAME" .
	sudo docker run --rm -v $PWD:/project "$DOCKER_IMAGE_NAME"
	sudo docker image rm "$DOCKER_IMAGE_NAME"
fi