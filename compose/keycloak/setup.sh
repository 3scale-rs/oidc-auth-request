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

call_token_endpoint_no_headers() {
	call_token_endpoint "${@}" | sed -E -e '0,/^[[:space:]]*$/d'
}

call_with_token() {
	local method="${1}"
	local url="${2}"
	local token="${3}"
	local payload="${4}"

	local response=$(curl -sSf -i -X "${method}" \
		-H "Authorization: Bearer ${token}" \
		-H "Content-Type: application/json" \
		-d "${payload}" \
		"${url}")

	[[ VERBOSE == "y" ]] && /bin/echo -e "call_with_token() ${url}:\n${response}" >&2
	echo "${response}"
}

call_with_token_no_headers() {
	call_with_token "${@}" | sed -E -e '0,/^[[:space:]]*$/d'
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

call_idp_no_headers() {
	call_idp "${@}" | sed -E -e '0,/^[[:space:]]*$/d'
}

get_auth_form() {
	local url="${1}"
	local realm="${2}"
	local client_id="${3:-test}"
	local scope="${4:-profile+email}"

	local url="${url}/auth/realms/${realm}/protocol/openid-connect/auth?client_id=${client_id}&response_type=code&scope=${scope}&redirect_uri=http%3A%2F%2F0.0.0.0%3A8080%2Foidc"
	local response=$(curl -sSf -i -c ./cookies -X GET \
		"${url}")

	[[ VERBOSE == "y" ]] && /bin/echo -e "get_auth_form() ${url}:\n${response}" >&2
	echo "${response}"
}

parse_auth_form() {
	local body="${1}"

	# XXX FIXME continue here
	# currently prints just http
	# echo '<form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="http://0.0.0.0:18080/auth/realms/master/login-actions/authenticate?session_code=HQntyAV0dKErLrBLCHQkFTnXSm-VJEbkmPgIkrFcBLk&amp;execution=de753dea-ca23-406a-8103-b6ecdccca4b3&amp;client_id=test&amp;tab_id=af78L1JMAS8" method="post">' | sed -n -E -e 's/<form id="kc-form-login".* action="([[:alnum:]]+).*"[ >]/\1/p'
	echo "${body}" | sed -n -E -e 's/<form id="kc-form-login".* action="([[:alnum:]]+).*"[ >]/\1/p'
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

	call_token_endpoint "${url}" "${realm}" "${client_id}" "password" "username=${user}&password=${passwd}"
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

	call_auth_token_password "${url}" "${realm}" "${client_id}" "${user}" "${passwd}" | sed -E -e '0,/^[[:space:]]*$/d' | jq -r ".access_token"
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
	call_with_token_no_headers GET "${url}/auth/admin/realms/${realm}/clients/${id}/client-secret" "${token}" | jq -r ".value"
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

	echo "-> Simulating we access the login form"
	get_auth_form "${url}" "${realm}" test
	echo "<- Got auth form"

	sleep 5

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
