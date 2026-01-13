# ChangeLog for crypton-x509-system

## 1.8.0

* Depend indirectly on package `time-hourglass`, rather than `hourglass`. Date
  and time-related types and classes are now those from the former package.
  [#18](https://github.com/kazu-yamamoto/crypton-certificate/pull/18)
* Depend indirectly on package `crypton-asn1-types >= 0.4.1` rather
  than `asn1-types`. ASN.1-related types and classes are now those from the
  former package.

## 1.6.8

* Prefer OpenSSL env vars: SSL_CERT_FILE and SSL_CERT_DIR
  [#26](https://github.com/kazu-yamamoto/crypton-certificate/pull/26)
* Unix defaultSystemPaths: add new Fedora default cert filepath
  [#19](https://github.com/kazu-yamamoto/crypton-certificate/pull/19)
