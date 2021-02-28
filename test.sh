#!/bin/bash

DOCKER_IMAGE=$(docker build -q --target test .)
LOG_FILE='/tmp/test.log'

i=1
while true; do
  echo -n "Test ${i}..."
  docker run --privileged --rm ${DOCKER_IMAGE} > "${LOG_FILE}"
  result=$?
  if [ $result -ne 0 ]; then
    echo 'FAIL'
    exit $result
  fi
  echo 'DONE'
  i=$((i+1))
done
