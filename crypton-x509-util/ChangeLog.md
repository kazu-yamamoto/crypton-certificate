# ChangeLog for crypton-x509-util

## v1.8.0

* Depend indirectly on package `time-hourglass`, rather than `hourglass`. Date
  and time-related types and classes are now those from the former package.
  [#18](https://github.com/kazu-yamamoto/crypton-certificate/pull/18)
* Depend on package `crypton-asn1-types >= 0.4.1` rather than `asn1-types`.
  ASN.1-related types and classes are now those from the former package.
