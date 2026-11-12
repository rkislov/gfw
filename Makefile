.PHONY: build css test check test-agent-linux test-network-linux test-firewall-linux test-services-linux test-package-linux test-pki test-wireguard-linux test-openvpn-linux test-ids-linux rpm rpm-alt-p11 deb-ubuntu-26.04 clean

build:
	go build -trimpath -o bin/gfwd ./cmd/gfwd
	go build -trimpath -o bin/gfw-agent ./cmd/gfw-agent

css:
	npm ci
	npm run build:css

test:
	go test -race ./...

check:
	go vet ./...
	node --check internal/web/assets/app.js
	node --check internal/web/assets/overview.js
	node --check internal/web/assets/network.js
	node --check internal/web/assets/policy.js
	node --check internal/web/assets/services.js
	node --check internal/web/assets/pki.js
	node --check internal/web/assets/wireguard.js
	node --check internal/web/assets/openvpn.js
	node --check internal/web/assets/openvpn-runtime.js
	node --check internal/web/assets/ipsec.js
	node --check internal/web/assets/feed.js
	node --check internal/web/assets/ids.js
	node --check internal/web/assets/traffic.js
	node --check internal/web/assets/capture.js
	node --check internal/web/assets/xdp.js
	node --check internal/web/assets/flow.js
	node --check internal/web/assets/fess.js
	node --check internal/web/assets/identity.js
	node --check internal/web/assets/sysctl.js

test-ids-linux:
	./scripts/test-ids-alt-p10.sh

test-openvpn-linux:
	./scripts/test-openvpn-alt-p10.sh

test-wireguard-linux:
	./scripts/test-wireguard-alt-p10.sh

test-firewall-linux:
	./scripts/test-firewall-alt-p10.sh

test-network-linux:
	./scripts/test-network-alt-p10.sh

test-agent-linux:
	./scripts/test-alt-p10.sh

test-pki: build
	python3 scripts/pki-lab.py

rpm:
	./scripts/build-rpm.sh

rpm-alt-p11:
	./scripts/build-rpm.sh altp11

deb-ubuntu-26.04:
	./scripts/build-package.sh ubuntu26.04

test-package-linux:
	./scripts/test-package-alt-p10.sh

test-services-linux:
	./scripts/test-services-alt-p10.sh

clean:
	rm -rf bin
