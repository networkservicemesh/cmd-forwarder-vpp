docker run --privileged "$(docker build -q --target test .)" > log.log
CONTAINER_NAME=$(docker ps -a | awk '{ if( FNR>1 ) { print $NF }}')
docker container cp "${CONTAINER_NAME}":./build/internal/tests/results/ /Users/user/Documents/dev/xored/cmd-forwarder-vpp/performance/iperf/
docker rm "${CONTAINER_NAME}"