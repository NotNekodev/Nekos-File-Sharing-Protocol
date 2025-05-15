.PHONY: all client server clean

all: client server certs

build: common client certs

client:
	$(MAKE) -C src/client

server:
	$(MAKE) -C src/server

certs:
	mkdir -p certs
	# Server certificate
	openssl genpkey -algorithm ED25519 -out certs/server_key.pem
	openssl req -new -x509 -key certs/server_key.pem -out certs/server_cert.pem -days 365 \
		-subj "/CN=NFSPServer"

	# Client certificate
	openssl genpkey -algorithm ED25519 -out certs/client_key.pem
	openssl req -new -x509 -key certs/client_key.pem -out certs/client_cert.pem -days 365 \
		-subj "/CN=NFSPClient"


clean:
	$(MAKE) -C src/client clean
	$(MAKE) -C src/server clean
