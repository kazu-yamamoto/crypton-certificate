# ChangeLog for crypton-x509-system

## 1.10.2

Support crypton-x509 1.11.

## 1.10.1

The system store contains only the certificates that the OS trusts for
TLS: the trust settings on macOS, and the Disallowed store and the
enhanced key usage property on Windows.

* macOS: load TLS anchors according to trust settings
  [#37](https://github.com/kazu-yamamoto/crypton-certificate/pull/37)
* Fix trust store loading
  [#38](https://github.com/kazu-yamamoto/crypton-certificate/pull/38)
* Windows: exclude disallowed roots and roots not enabled for TLS
  [#45](https://github.com/kazu-yamamoto/crypton-certificate/pull/45)

## 1.10.0

* Follow the breaking change in `crypton-x509` 1.10.0
  [#35](https://github.com/kazu-yamamoto/crypton-certificate/pull/35)

## 1.9.0

* Using "ram" instead of "memory"
  [#29](https://github.com/kazu-yamamoto/crypton-certificate/pull/29)

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
