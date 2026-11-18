# ChangeLog for crypton-x509-validation

## 1.10.3

MD2 and MD5 signatures are rejected, and certification paths are built
with backtracking.

* Harden certificate validation
  [#44](https://github.com/kazu-yamamoto/crypton-certificate/pull/44)
* Accept and encode valid structures in crypton-x509
  [#46](https://github.com/kazu-yamamoto/crypton-certificate/pull/46)
* Build certification paths with backtracking and implement CRL distribution points
  [#48](https://github.com/kazu-yamamoto/crypton-certificate/pull/48)
* Small fixes for EC keys, RSA verification and EKU
  [#50](https://github.com/kazu-yamamoto/crypton-certificate/pull/50)

## 1.10.2

* Fix host name validation with iPAddress SANs: an IP address is
  matched only against iPAddress SANs and the CN is not used if the
  SubjectAltName extension is present, even without dNSName.
* An IP address is no longer matched against the CN of a certificate
  without SubjectAltName.

## 1.10.1

* Fix name constraint bypasses: constraints are accumulated per RFC
  5280, apply to the leaf even if self-issued and to the CN used as a
  host name, dNSName matching is case-insensitive, and iPAddress,
  rfc822Name, URI and directoryName constraints are enforced.
* Undecodable NameConstraints, BasicConstraints, KeyUsage,
  ExtendedKeyUsage and SubjectAltName extensions fail validation
  instead of being ignored.
* Reject degenerate DSA parameters and oversized RSA keys before
  verifying signatures.
* Limit the chain depth to 20 CA certificates.

## 1.10.0

* Verify ML-DSA signatures
  [#35](https://github.com/kazu-yamamoto/crypton-certificate/pull/35)
* Follow the breaking change in `crypton-x509` 1.10.0
  [#35](https://github.com/kazu-yamamoto/crypton-certificate/pull/35)

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
