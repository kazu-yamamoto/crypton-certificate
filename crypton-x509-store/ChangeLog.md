# ChangeLog for crypton-x509-store

## v1.8.0

* Depend on package `crypton-asn1-types >= 0.4.1` rather than `asn1-types`.
  ASN.1-related types and classes are now those from the former package.
  [#18](https://github.com/kazu-yamamoto/crypton-certificate/pull/18)
* Swap crypton-pem for existing unmaintained pem dependency.
  [#16](https://github.com/kazu-yamamoto/crypton-certificate/pull/16)

## v1.6.14

* Defining MIN_VERSION_unix if not defined.
  [#27](https://github.com/kazu-yamamoto/crypton-certificate/issues/27)

## v1.6.13

* Making buildable with ghc-9.4 and ghc-9.2.
  [#23](https://github.com/kazu-yamamoto/crypton-certificate/pull/23)
