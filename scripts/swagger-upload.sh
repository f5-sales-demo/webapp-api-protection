#!/usr/bin/env bash
# Upload an OpenAPI/Swagger file to the F5 XC object store ONCE and print the
# resulting object-store path to pin into api_definition_swagger_specs.
#
# xcsh_api_definition.swagger_specs are NOT inline bodies — they are object-store
# paths of uploaded files (server rule:
# /api/object_store/namespaces/<ns>/stored_objects/swagger/<name>/<version>).
# The store is content-addressed: re-uploading identical content returns the same
# server-assigned, date-stamped version, so this helper is idempotent; changing the
# content mints a new version. Because the version token is only known after upload
# (and embeds the upload date), seal ONCE and pin the printed path — the same
# discipline as scripts/blindfold-seal.sh. Never regenerate the path inline.
#
# Usage: swagger-upload.sh <name> <openapi-file> [namespace]
#   Requires XCSH_API_URL + XCSH_API_TOKEN in the environment.
#   <name> is the stored-object name (DNS-ish, e.g. vampi). <openapi-file> is a
#   local JSON/YAML OpenAPI document. namespace defaults to webapp-api-protection.
set -euo pipefail

NAME="${1:?usage: swagger-upload.sh <name> <openapi-file> [namespace]}"
FILE="${2:?usage: swagger-upload.sh <name> <openapi-file> [namespace]}"
NS="${3:-webapp-api-protection}"
: "${XCSH_API_URL:?XCSH_API_URL must be set}"
: "${XCSH_API_TOKEN:?XCSH_API_TOKEN must be set}"

[ -r "$FILE" ] || {
  echo "cannot read $FILE" >&2
  exit 1
}
case "$FILE" in
*.yaml | *.yml) FMT="yaml" ;;
*) FMT="json" ;;
esac

H="Authorization: APIToken $XCSH_API_TOKEN"
umask 077
BODY=$(mktemp)
LISTING=$(mktemp)
trap 'rm -f "$BODY" "$LISTING"' EXIT

# Build the PUT body: string_value carries the file text (JSON-encoded).
python3 - "$NS" "$NAME" "$FMT" "$FILE" >"$BODY" <<'PY'
import json, sys
ns, name, fmt, path = sys.argv[1:5]
with open(path, "r", encoding="utf-8") as fh:
    contents = fh.read()
print(json.dumps({
    "namespace": ns, "object_type": "swagger", "name": name,
    "string_value": contents, "content_format": fmt,
}))
PY

code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "$H" -H "Content-Type: application/json" \
  --data @"$BODY" "$XCSH_API_URL/api/object_store/namespaces/$NS/stored_objects/swagger/$NAME")
[ "$code" = "200" ] || {
  echo "upload failed (HTTP $code)" >&2
  exit 1
}

# Read back the latest version and print the pinned object-store PATH (not the URL).
# The listing goes to a file so the heredoc-fed python does not clash with a pipe.
curl -s -H "$H" "$XCSH_API_URL/api/object_store/namespaces/$NS/stored_objects/swagger" >"$LISTING"
python3 - "$NS" "$NAME" "$LISTING" <<'PY'
import json, sys
ns, name, listing = sys.argv[1], sys.argv[2], sys.argv[3]
with open(listing, "r", encoding="utf-8") as fh:
    data = json.load(fh)
want = f"{ns}/{name}"
item = next((i for i in data.get("items", []) if i.get("name") == want), None)
if item is None:
    sys.exit(f"uploaded object {want} not found in listing")
versions = item.get("versions", [])
latest = next((v for v in versions if v.get("latest_version")), versions[-1] if versions else None)
if latest is None:
    sys.exit(f"uploaded object {want} has no version in listing")
print(f"/api/object_store/namespaces/{ns}/stored_objects/swagger/{name}/{latest['version']}")
PY
