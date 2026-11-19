.PHONY: image fixtures build proof release test clean fclean fmt fmt-check

IMAGE = 0th-circuit-tools

# A download that fails leaves no partial file behind
.DELETE_ON_ERROR:

# PSE's Perpetual Powers of Tau, contribution 80, prepared for circuits up to 2^20 constraints
PTAU_URL = https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_20.ptau
PTAU_B2SUM = 117b49e5570b4490b9377962c295e369506116e1db6ee035a7a28bcd83011366297bc486ca8df6cb62f247e2fd0f52d44c892ea4f033393457fbb264a59c75ac

CIRCOM_SOURCES = $(shell find src -name '*.circom')

# What the release publishes, with b2sums.txt beside it in target/release
RELEASE = target/login.r1cs target/login.zkey target/vk.json target/login-witness target/login-witness.dat \
	target/proof.json target/public.json fixtures/fixture.json fixtures/input.json

# The tools run in an x86_64 image: circom, rapidsnark and the witness generator's assembly are x86_64
image:
	docker build --platform linux/amd64 -t $(IMAGE) .

RUN = docker run --rm --user "$$(id -u):$$(id -g)" -v "$$(pwd)":/work $(IMAGE) bash -c

SNARKJS = node node_modules/snarkjs/build/cli.cjs

fixtures:
	node scripts/fixture.ts

# The constraints, the wasm witness generator and the C++ one's source, all with the same --O2:
# a witness from another optimisation level lists the signals in another order
target/login.r1cs target/login_js/login.wasm target/login_cpp/login.cpp &: $(CIRCOM_SOURCES) | image
	mkdir -p target
	$(RUN) 'circom src/login.circom --r1cs --wasm --c --O2 -l node_modules -o target'

build: target/login.r1cs

# The C++ witness generator reads its constants from the file at its own path plus .dat
target/login-witness target/login-witness.dat &: target/login_cpp/login.cpp
	$(RUN) 'make -s -C target/login_cpp'
	cp target/login_cpp/login target/login-witness
	cp target/login_cpp/login.dat target/login-witness.dat

target/pot20.ptau:
	mkdir -p target
	curl -fsSL $(PTAU_URL) -o $@
	echo "$(PTAU_B2SUM)  $@" | b2sum -c

# The proving key from a single contribution. Whoever makes it could keep its secret and forge any
# proof, so a key made here is for testnets only. snarkjs reads "zkey verify init" as "zkey verify r1cs",
# so the check against the initial key is called by its alias zkvi
target/login.zkey: target/login.r1cs target/pot20.ptau
	$(RUN) '\
		export NODE_OPTIONS=--max-old-space-size=12000 && \
		$(SNARKJS) groth16 setup target/login.r1cs target/pot20.ptau /tmp/login_0000.zkey && \
		$(SNARKJS) zkey contribute /tmp/login_0000.zkey $@ --name=release \
			-e="$$(head -c 64 /dev/urandom | base64 -w0)" && \
		$(SNARKJS) zkvi /tmp/login_0000.zkey target/pot20.ptau $@ \
	'

target/vk.json: target/login.zkey
	$(RUN) '$(SNARKJS) zkey export verificationkey $< $@'

# The fixture letter's proof, made as the server makes one. rapidsnark leaves out the curve, which
# Garaga's parsers read after the proof's points
target/proof.json target/public.json &: target/login-witness target/vk.json fixtures/input.json
	$(RUN) '\
		target/login-witness fixtures/input.json /tmp/witness.wtns && \
		rapidsnark target/login.zkey /tmp/witness.wtns target/proof.json target/public.json && \
		sed -i "s/}$$/,\"curve\":\"bn128\"}/" target/proof.json && \
		$(SNARKJS) groth16 verify target/vk.json target/public.json target/proof.json \
	'

proof: target/proof.json

release: $(RELEASE)
	rm -rf target/release && mkdir -p target/release
	cp -l $(RELEASE) target/release/
	cd target/release && b2sum * > b2sums.txt

test: target/login.r1cs
	pnpm test

clean:
	rm -rf target

fclean: clean
	docker rmi $(IMAGE) 2>/dev/null || true

fmt:
	pnpm run fmt

fmt-check:
	pnpm run fmt-check
