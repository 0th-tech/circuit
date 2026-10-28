.PHONY: image fixtures build proof test clean fclean fmt fmt-check

IMAGE = 0th-circuit-tools
NARGO_CACHE = 0th-circuit-nargo-cache

image:
	docker build -t $(IMAGE) .
	docker volume create $(NARGO_CACHE) > /dev/null
	docker run --rm -v $(NARGO_CACHE):/root/nargo $(IMAGE) chmod a+rwX /root/nargo

RUN = docker run --rm --user "$$(id -u):$$(id -g)" \
	-v "$$(pwd)":/work -v $(NARGO_CACHE):/root/nargo $(IMAGE) bash -c

fixtures:
	node scripts/fixture.ts
	nargo fmt

# target/login.json and target/vk
build: image
	$(RUN) '\
		nargo compile && \
		mkdir -p target/.bb-crs && \
		bb write_vk -s ultra_honk --oracle_hash keccak -b target/login.json -o target/ -c target/.bb-crs \
	'

# target/proof and target/public_inputs, from the fixture letter in Prover.toml
proof: build
	$(RUN) '\
		nargo execute witness && \
		bb prove -s ultra_honk --oracle_hash keccak -b target/login.json -w target/witness.gz -o target/ -c target/.bb-crs \
	'

test:
	nargo test

clean:
	rm -rf target

fclean: clean
	docker rmi $(IMAGE) 2>/dev/null || true
	docker volume rm $(NARGO_CACHE) 2>/dev/null || true

fmt:
	nargo fmt
	pnpm run fmt

fmt-check:
	nargo fmt --check
	pnpm run fmt-check
