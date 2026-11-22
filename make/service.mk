# Service-specific targets of api-gateway-service. The Makefile loads this file with `-include`;
# the template ships no such file, so a template sync never changes it. Every target here is
# documented in docs/make-targets-service.md.

.PHONY: bench-spikes schemathesis-iam

bench-spikes: ## Run the phase-0 spike benches (RS256 verify, GraphQL parse); never part of make ci
	mkdir -p target/reports/bench-spikes
	$(EXEC) bash -c 'set -o pipefail; cargo bench --locked -p service --bench spikes 2>&1 | tee target/reports/bench-spikes/spikes.txt'

schemathesis-iam: ## Run Schemathesis with an ephemeral ROLE_SERVICE token so it reaches the IAM operations past the 401; never part of make ci
	$(REQUIRE_DOCKER)
	scripts/schemathesis-iam.sh
