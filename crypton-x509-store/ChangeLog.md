# ChangeLog for crypton-x509-store

## v1.8.0

- Depend indirectly on package `time-hourglass`, rather than `hourglass`. Date
  and time-related types and classes are now those from the former package.
- Depend on package `crypton-asn1-types >= 0.4.1` rather than `asn1-types`.
  ASN.1-related types and classes are now those from the former package.

## v1.6.13

* Making buildable with ghc-9.4 and ghc-9.2.
  [#23](https://github.com/kazu-yamamoto/crypton-certificate/pull/23)
