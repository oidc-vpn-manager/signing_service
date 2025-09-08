#!/bin/sh
#
# This script copies PKI files from a source directory to a target
# shared volume and sets their ownership. It's designed to be used
# as an init container.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Validate Environment Variables ---
if [ -z "${SOURCE_CERT_PATH}" ] || [ -z "${SOURCE_KEY_PATH}" ]; then
  echo "ERROR: SOURCE_CERT_PATH and SOURCE_KEY_PATH must be defined." >&2
  exit 1
fi

if [ -z "${TARGET_CERT_PATH}" ] || [ -z "${TARGET_KEY_PATH}" ]; then
  echo "ERROR: TARGET_CERT_PATH and TARGET_KEY_PATH must be defined." >&2
  exit 1
fi

if [ -z "${TARGET_UID}" ] || [ -z "${TARGET_GID}" ]; then
  echo "ERROR: TARGET_UID and TARGET_GID must be defined." >&2
  exit 1
fi

# --- Validate Source Files ---
if [ ! -f "${SOURCE_CERT_PATH}" ]; then
  echo "ERROR: Source certificate not found at ${SOURCE_CERT_PATH}" >&2
  exit 1
fi

if [ ! -f "${SOURCE_KEY_PATH}" ]; then
  echo "ERROR: Source key not found at ${SOURCE_KEY_PATH}" >&2
  exit 1
fi

# --- Copy Files if They Have Changed ---
echo "Checking certificate..."
if ! cmp -s "${SOURCE_CERT_PATH}" "${TARGET_CERT_PATH}"; then
  echo "Certificate has changed. Copying..."
  install -o "${TARGET_UID}" -g "${TARGET_GID}" -m 644 "${SOURCE_CERT_PATH}" "${TARGET_CERT_PATH}"
else
  echo "Certificate is unchanged."
fi

echo "Checking private key..."
if ! cmp -s "${SOURCE_KEY_PATH}" "${TARGET_KEY_PATH}"; then
  echo "Private key has changed. Copying..."
  install -o "${TARGET_UID}" -g "${TARGET_GID}" -m 600 "${SOURCE_KEY_PATH}" "${TARGET_KEY_PATH}"
else
  echo "Private key is unchanged."
fi

echo "PKI initialization complete."
exit 0