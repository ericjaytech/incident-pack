#!/usr/bin/env bats

setup() {
	repository_root="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
	service_collector="$repository_root/src/incident_pack/collectors/service.sh"
	resource_collector="$repository_root/src/incident_pack/collectors/resources.sh"
}

@test "service collector returns bounded protocol output" {
	run "$service_collector" incident-pack-definitely-missing.service

	[ "$status" -eq 0 ]
	[ -n "$output" ]
	[ "${#output}" -le 8192 ]
}

@test "service collector does not evaluate service input" {
	marker="$BATS_TEST_TMPDIR/must-not-exist"

	run "$service_collector" "missing.service;touch $marker"

	[ "$status" -eq 0 ]
	[ ! -e "$marker" ]
}

@test "resource collector returns bounded protocol output" {
	run "$resource_collector"

	[ "$status" -eq 0 ]
	[ -n "$output" ]
	[ "${#output}" -le 65536 ]
	[[ "$output" == *"LOAD"* || "$output" == *"UNAVAILABLE"* ]]
}
