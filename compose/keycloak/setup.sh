#!/bin/bash

call_admin_cli() {
	local method="${1}"
	local url="${2}"
	local user="${3}"
	local passwd="${4}"

	local response=$(curl -sSfL -X "${method}" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "username=${user}" \
		-d "password=${passwd}" \
		-d "grant_type=password" \
		-d "client_id=admin-cli" \
		"${url}")

	[[ VERBOSE == "y" ]] && /bin/echo -e "call_admin_cli() ${url}:\n${response}" >&2
	echo "${response}"
}

call_token() {
	local method="${1}"
	local url="${2}"
	local token="${3}"
	local payload="${4}"

	local response=$(curl -sSfL -X "${method}" \
		-H "Authorization: Bearer ${token}" \
		-H "Content-Type: application/json" \
		-d "${payload}" \
		"${url}")

	[[ VERBOSE == "y" ]] && /bin/echo -e "call_token() ${url}:\n${response}" >&2
	echo "${response}"
}

get_access_token() {
	local url="${1}"
	local realm="${2}"
	local user="${3}"
	local passwd="${4}"

	call_admin_cli POST "${url}/auth/realms/${realm}/protocol/openid-connect/token" "${user}" "${passwd}" | jq -r ".access_token"
}

add_client() {
	local url="${1}"
	local realm="${2}"
	local token="${3}"
	local id="${4}"
	local name="${5}"

	call_token POST "${url}/auth/admin/realms/${realm}/clients" "${token}" '{ "id": "test", "name": "test", "redirectUris": ["*"] }'
}

get_client_secret() {
	local url="${1}"
	local realm="${2}"
	local token="${3}"
	local id="${4}"

	call_token GET "${url}/auth/admin/realms/${realm}/clients/${id}/client-secret" "${token}" '{ "id": "test", "name": "test", "redirectUris": ["*"] }' | jq -r ".value"
}

main() {
	local url="${1}"
	local realm="${2}"

	if test "x${url}" = "x"; then
		echo >&2 "No Keycloak URL specified, taking default http://0.0.0.0:18080"
		url="http://0.0.0.0:18080"
	fi
	if test "x${realm}" = "x"; then
		echo >&2 "No realm specified, taking default master"
		realm="master"
	fi

	echo "-> Retrieving token from ${url}..."
	TOKEN=$(get_access_token "${url}" "${realm}" "${3:-admin}" "${4:-admin}")
	echo "<- Got token: ${TOKEN}"

	echo "-> Creating new client test... (might fail if pre-existing)"
	add_client "${url}" "${realm}" "${TOKEN}" test test || true
	echo "<- Done"

	echo "-> Retrieving client secret for test..."
	SECRET=$(get_client_secret "${url}" "${realm}" "${TOKEN}" test)
	echo "<- Got secret: ${SECRET}"
}

if [[ "${BASH_SOURCE[0]}" = "${0}" ]]; then
	set -eo pipefail
	shopt -s failglob

	main "${@}"
fi
