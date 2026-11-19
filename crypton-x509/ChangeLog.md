# ChangeLog for crypton-x509

## 1.11.0

* Keep RSA-PSS parameters
  [#53](https://github.com/kazu-yamamoto/crypton-certificate/pull/53)
* Keep multi-valued RDNs
  [#54](https://github.com/kazu-yamamoto/crypton-certificate/pull/54)
* Represent X9.42 DH public keys
  [#55](https://github.com/kazu-yamamoto/crypton-certificate/pull/55)
* Keep all GeneralName forms
  [#57](https://github.com/kazu-yamamoto/crypton-certificate/pull/57)
* Keep all fields of AuthorityKeyIdentifier
  [#58](https://github.com/kazu-yamamoto/crypton-certificate/pull/58)
* Keep all fields of DistributionPoint
  [#59](https://github.com/kazu-yamamoto/crypton-certificate/pull/59)
* Add more DnElement attributes
  [#60](https://github.com/kazu-yamamoto/crypton-certificate/pull/60)
* Support RSASSA-PSS keys
  [#61](https://github.com/kazu-yamamoto/crypton-certificate/pull/61)
* Support SHA-3 signature algorithms
  [#62](https://github.com/kazu-yamamoto/crypton-certificate/pull/62)

## 1.10.3

Parsing is stricter: certificates with data after the public key,
duplicate extensions or trailing data are rejected.

* Omit AlgorithmIdentifier parameters for ECDSA and DSA signatures
  [#32](https://github.com/kazu-yamamoto/crypton-certificate/pull/32)
* Make certificate parsing stricter
  [#39](https://github.com/kazu-yamamoto/crypton-certificate/pull/39)
* Accept and encode valid structures in crypton-x509
  [#46](https://github.com/kazu-yamamoto/crypton-certificate/pull/46)
* Build certification paths with backtracking and implement CRL distribution points
  [#48](https://github.com/kazu-yamamoto/crypton-certificate/pull/48)
* Small fixes for EC keys, RSA verification and EKU
  [#50](https://github.com/kazu-yamamoto/crypton-certificate/pull/50)

## 1.10.2

* Reject iPAddress GeneralNames of invalid length in SubjectAltName
  (4 or 16 bytes) and NameConstraints (8 or 32 bytes).

## 1.10.1

* Decoding functions return `Left` instead of throwing on malformed
  input (lazy decoder errors, unknown key usage bits, non-OID extended
  key usage, CRL distribution points, invalid strings).
* Fix the encoding of NameConstraints, which its own decoder could not
  read, and of directoryName and dNSSRV GeneralNames.
* SubjectAltName decoding skips unsupported GeneralName types.

## 1.10.0

* Support ML-DSA (RFC 9881)
  [#35](https://github.com/kazu-yamamoto/crypton-certificate/pull/35)
* An ML-DSA private key keeps the form it was written in
  [#35](https://github.com/kazu-yamamoto/crypton-certificate/pull/35)

## 1.9.2

* Stop printing EC private keys
  [#34](https://github.com/kazu-yamamoto/crypton-certificate/pull/34)

## 1.9.1

* Implementing the X509 name constrains extension.
  [#30](https://github.com/kazu-yamamoto/crypton-certificate/pull/30)

## 1.9.0

* Using "ram" instead of "memory"
  [#29](https://github.com/kazu-yamamoto/crypton-certificate/pull/29)

## 1.8.0

* Depend on package `time-hourglass`, rather than `hourglass`. Date and
  time-related types and classes are now those from the former package.
  [#18](https://github.com/kazu-yamamoto/crypton-certificate/pull/18)
* Depend on package `crypton-asn1-types >= 0.4.1` rather than `asn1-types`.
  ASN.1-related types and classes are now those from the former package.

## 1.7.7

* Bump requirements to GHC 7.8 and transformers 0.4 series
  [#130](https://github.com/haskell-tls/hs-certificate/pull/130)
