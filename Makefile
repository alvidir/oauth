BINARY_NAME=tykhe
VERSION?=latest
PKG_MANAGER?=dnf

features_grpc="grpc postgres redis-cache rabbitmq smtp tracer"
features_rest="rest tracer"

all: binaries

binaries: install-deps
ifdef target
	cargo build --bin $(target) --no-default-features --features=$(features_$(target)) --release
else
	-cargo build --bin grpc --no-default-features --features=$(features_grpc) --release
	-cargo build --bin rest --no-default-features --features=$(features_rest) --release
endif

images:
ifdef target
	podman build -t alvidir/$(BINARY_NAME):$(VERSION)-$(target) -f ./container/$(target)/containerfile .
else
	-podman build -t alvidir/$(BINARY_NAME):$(VERSION)-grpc -f ./container/grpc/containerfile .
	-podman build -t alvidir/$(BINARY_NAME):$(VERSION)-rest -f ./container/rest/containerfile .
endif

push-images:
ifdef target
	@podman push alvidir/$(BINARY_NAME):$(VERSION)-$(target)
else
	@-podman push alvidir/$(BINARY_NAME):$(VERSION)-grpc
	@-podman push alvidir/$(BINARY_NAME):$(VERSION)-rest
endif

install-deps:
	-$(PKG_MANAGER) install -y protobuf-compiler
	-$(PKG_MANAGER) install -y postgresql-devel
	-$(PKG_MANAGER) install -y openssl-devel
	-$(PKG_MANAGER) install -y pkg-config

clean:
	@-cargo clean
	@-rm -rf bin/                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     o
	@-rm -rf secrets/

clean-images:
	@-podman image rm alvidir/$(BINARY_NAME):$(VERSION)-grpc
	@-podman image rm alvidir/$(BINARY_NAME):$(VERSION)-rest
	
test:
	@RUST_BACKTRACE=full cargo test --no-default-features -- --nocapture

secrets:
	@mkdir -p secrets/
	@openssl ecparam -name prime256v1 -genkey -noout -out secrets/ec_key.pem
	@openssl ec -in secrets/ec_key.pem -pubout -out secrets/ec_pubkey.pem
	@openssl pkcs8 -topk8 -nocrypt -in secrets/ec_key.pem -out secrets/pkcs8_key.pem
	@cat secrets/ec_key.pem | base64 | tr -d '\n' > secrets/ec_key.base64
	@cat secrets/ec_pubkey.pem | base64 | tr -d '\n' > secrets/ec_pubkey.base64
	@cat secrets/pkcs8_key.pem | base64 | tr -d '\n' > secrets/pkcs8_key.base64

deploy:
	@python3 scripts/build_db_setup_script.py
	@podman-compose -f compose.yaml up -d

undeploy:
	@podman-compose -f compose.yaml down