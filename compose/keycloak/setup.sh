#!/bin/bash

call_token_endpoint() {
	local url="${1}"
	local realm="${2}"
	local client_id="${3}"
	local grant_type="${4}"
	local payload="${5}"
	#local user="${5}"
	#local passwd="${6}"

	local response=$(curl -sSf -i -X POST \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=${grant_type}" \
		-d "client_id=${client_id}" \
		-d "${payload}" \
		"${url}/auth/realms/${realm}/protocol/openid-connect/token")

	[[ VERBOSE == "y" ]] && /bin/echo -e "call_token_endpoint() ${url}:\n${response}" >&2
	echo "${response}"
}

call_with_token() {
	local method="${1}"
	local url="${2}"
	local token="${3}"
	local payload="${4}"

	local response=$(curl -sSfL -X "${method}" \
		-H "Authorization: Bearer ${token}" \
		-H "Content-Type: application/json" \
		-d "${payload}" \
		"${url}")

	[[ VERBOSE == "y" ]] && /bin/echo -e "call_with_token() ${url}:\n${response}" >&2
	echo "${response}"
}

call_idp() {
	local method="${1}"
	local url="${2}"
	local ctype="${3}"
	local payload="${4}"

	local response=$(curl -sSf -i -X "${method}" \
		-H "Content-Type: ${ctype}" \
		-d "${payload}" \
		"${url}")

	[[ VERBOSE == "y" ]] && /bin/echo -e "call_idp() ${url}:\n${response}" >&2
	echo "${response}"
}

# gets back a code
login() {
	local url="${1}"
	local realm="${2}"
	local user="${3}"
	local passwd="${4}"
	local client_id="${5}"
	local session_code="${6}"
	local execution="${7}"
	local tab_id="${8}"

	#call_idp "POST" "${url}/auth/realms/${realm}/login-actions/authenticate?session_code=${session_code}&execution=${execution}&client_id=${client_id}&tab_id=${tab_id}" "application/x-www-form-urlencoded" "username=${user}&password=${passwd}&credentialId="
	call_idp "POST" "${url}/auth/realms/${realm}/login-actions/authenticate?client_id=${client_id}" "application/x-www-form-urlencoded" "username=${user}&password=${passwd}&credentialId=" | grep -i "^Location: " | cut -d' ' -f 2- | grep -o -E -e "[\&\?]code=([^&])*" | cut -d'=' -f 2-
}

# Generates JSON with an access token
call_auth_token_password() {
	local url="${1}"
	local realm="${2}"
	local client_id="${3}"
	local user="${4}"
	local passwd="${5}"

	call_token_endpoint "${url}" "${realm}" "${client_id}" "password" "user=${user}&password=${passwd}"
}

# Generates a Location with the right credentials for JWT authn
call_auth_token_code() {
	local url="${1}"
	local realm="${2}"
	local client_id="${3}"
	local code="${4}"
	local client_secret="${5}"
	local redirect_uri="${6:-"http%3A%2F%2F0.0.0.0%3A8080%2Foidc"}"

	#call_idp "POST" "${url}/auth/realms/${realm}/protocol/openid-connect/token" "application/x-www-form-urlencoded" "grant_type=authorization_code&code=${code}&redirect_uri=http%3A%2F%2F0.0.0.0%3A8080%2Foidc&client_id=test&client_secret=${client_secret}"
	call_token_endpoint "${url}" "${realm}" "${client_id}" "authorization_code" "code=${code}&client_secret=${client_secret}&redirect_uri=${redirect_uri}"
}

get_access_token() {
	local url="${1}"
	local realm="${2}"
	local client_id="${3}"
	local user="${4}"
	local passwd="${5}"

	call_auth_token_password "${url}" "${realm}" "${client_id}" "${user}" "${passwd}" | jq -r ".access_token"
}

add_client() {
	local url="${1}"
	local realm="${2}"
	local token="${3}"
	local id="${4}"
	local name="${5}"

	call_with_token POST "${url}/auth/admin/realms/${realm}/clients" "${token}" '{ "id": "test", "name": "test", "redirectUris": ["*"] }'
}

get_client_secret() {
	local url="${1}"
	local realm="${2}"
	local token="${3}"
	local id="${4}"

	#call_with_token GET "${url}/auth/admin/realms/${realm}/clients/${id}/client-secret" "${token}" '{ "id": "test", "name": "test", "redirectUris": ["*"] }' | jq -r ".value"
	call_with_token GET "${url}/auth/admin/realms/${realm}/clients/${id}/client-secret" "${token}" | jq -r ".value"
}

main() {
	local url="${1}"
	local realm="${2}"
	local user="${3:-admin}"
	local passwd="${4:-admin}"

	if test "x${url}" = "x"; then
		echo >&2 "No Keycloak URL specified, taking default http://0.0.0.0:18080"
		url="http://0.0.0.0:18080"
	fi
	if test "x${realm}" = "x"; then
		echo >&2 "No realm specified, taking default master"
		realm="master"
	fi

	echo "-> Retrieving token for admin-cli from ${url}..."
	TOKEN=$(get_access_token "${url}" "${realm}" "admin-cli" "${user}" "${passwd}")
	echo "<- Got token: ${TOKEN}"

	sleep 2

	echo "-> Creating new client test via token... (might fail if pre-existing)"
	add_client "${url}" "${realm}" "${TOKEN}" test test || true
	echo "<- Done"

	sleep 1

	echo "-> Retrieving client secret for test..."
	CLIENT_SECRET=$(get_client_secret "${url}" "${realm}" "${TOKEN}" test)
	echo "<- Got client secret: ${CLIENT_SECRET}"

	echo "=== Setup done ==="
	sleep 3

	echo "=== Init auth flow via browser by requesting code for test via administrative user/passwd authentication against IDP ==="

	sleep 1

	echo "-> Login via browser using admin credentials to request a temporary authz code for test application"
	CODE=$(login "${url}" "${realm}" "${user}" "${passwd}" test)
	echo "<- Got code: ${CODE}"

	sleep 2

	echo "-> Using test client authz code along client secret"
	call_auth_token_code "${url}" "${realm}" test "${CODE}" "${CLIENT_SECRET}"
	echo "<- Done"
}

if [[ "${BASH_SOURCE[0]}" = "${0}" ]]; then
	set -exo pipefail
	shopt -s failglob

	main "${@}"
fi
