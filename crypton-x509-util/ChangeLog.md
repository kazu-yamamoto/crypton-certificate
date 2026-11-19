# ChangeLog for crypton-x509-util

## 1.9.3

Support crypton-x509 1.11.

* Support RSASSA-PSS keys
  [#61](https://github.com/kazu-yamamoto/crypton-certificate/pull/61)
* Support ML-KEM keys
  [#63](https://github.com/kazu-yamamoto/crypton-certificate/pull/63)

## 1.9.2

* Fix trust store loading
  [#38](https://github.com/kazu-yamamoto/crypton-certificate/pull/38)

## 1.9.1

* Show ML-DSA keys, with the seed when the file held one
  [#35](https://github.com/kazu-yamamoto/crypton-certificate/pull/35)

## 1.9.0

* Using "ram" instead of "memory"
  [#29](https://github.com/kazu-yamamoto/crypton-certificate/pull/29)

## v1.8.0

* Depend indirectly on package `time-hourglass`, rather than `hourglass`. Date
  and time-related types and classes are now those from the former package.
  [#18](https://github.com/kazu-yamamoto/crypton-certificate/pull/18)
* Depend on package `crypton-asn1-types >= 0.4.1` rather than `asn1-types`.
  ASN.1-related types and classes are now those from the former package.
