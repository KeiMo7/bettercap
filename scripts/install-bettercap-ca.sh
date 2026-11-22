#!/usr/bin/env bash
set -euo pipefail

CERT_PATH="${1:-${HOME}/.bettercap-ca.cert.pem}"

if [[ ! -f "${CERT_PATH}" ]]; then
  echo "CA certificate not found: ${CERT_PATH}" >&2
  echo "Start https.proxy once so BetterCAP generates it, or pass the path as the first argument." >&2
  exit 1
fi

if command -v openssl >/dev/null 2>&1; then
  openssl x509 -in "${CERT_PATH}" -noout >/dev/null
fi

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

case "$(uname -s)" in
  Linux)
    if command -v update-ca-certificates >/dev/null 2>&1; then
      run_root install -m 0644 "${CERT_PATH}" /usr/local/share/ca-certificates/bettercap-ca.crt
      run_root update-ca-certificates
    elif command -v update-ca-trust >/dev/null 2>&1; then
      run_root install -m 0644 "${CERT_PATH}" /etc/pki/ca-trust/source/anchors/bettercap-ca.crt
      run_root update-ca-trust extract
    else
      echo "No supported system trust tool found (update-ca-certificates or update-ca-trust)." >&2
      exit 1
    fi

    if command -v certutil >/dev/null 2>&1 && [[ -d "${HOME}/.pki/nssdb" ]]; then
      certutil -d "sql:${HOME}/.pki/nssdb" -A -t "C,," -n "bettercap-ca" -i "${CERT_PATH}"
    fi
    ;;
  Darwin)
    run_root security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain "${CERT_PATH}"
    ;;
  *)
    echo "Unsupported OS: $(uname -s). Use scripts/install-bettercap-ca.ps1 on Windows." >&2
    exit 1
    ;;
esac

echo "Installed the BetterCAP CA from ${CERT_PATH}."
echo "Restart the browser or client application."
echo "Firefox, Java and applications with a private trust store or certificate pinning"
echo "will keep using passthrough instead of decryption."
echo "Remove the CA from the OS trust store when you no longer need HTTPS inspection."
