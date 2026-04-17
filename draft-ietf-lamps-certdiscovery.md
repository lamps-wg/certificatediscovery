---
title: "A Mechanism for X.509 Certificate Discovery"
abbrev: "TODO - Abbreviation"
category: std

docname: draft-ietf-lamps-certdiscovery-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - Algorithm Agility
 - Operational Redundancy
 - Dual Use
venue:
#  group: WG
#  type: Working Group
#  mail: spasm@ietf.org
#  arch: https://mailarchive.ietf.org/arch/browse/spasm/
  github: "lamps-wg/certificatediscovery"
  latest: "https://lamps-wg.github.io/certificatediscovery/draft-ietf-lamps-certdiscovery.html"

author:
 -
    ins: T. Okubo
    fullname: Tomofumi Okubo
    organization: Penguin Securities Pte. Ltd.
    email: tomofumi.okubo+ietf@gmail.com

 -
    ins: C. Bonnell
    fullname: Corey Bonnell
    organization: DigiCert, Inc.
    email: corey.bonnell@digicert.com

 -
    ins: J. Gray
    fullname: John Gray
    organization: Entrust
    email: john.gray@entrust.com

 -
    ins: M. Ounsworth
    fullname: Mike Ounsworth
    organization: Entrust
    email: mike.ounsworth@entrust.com

 -
    ins: J. Mandel
    fullname: Joe Mandel
    organization: AKAYLA, Inc.
    email: joe@akayla.com

normative:

informative:


--- abstract

This document specifies a method to discover a secondary X.509 certificate associated with an X.509 certificate to enable efficient multi-certificate handling in protocols. The objective is threefold: to enhance cryptographic agility, improve operational availability, and accommodate multi-key/certificate usage. The proposed method aims to maximize compatibility with existing systems and is designed to be legacy-friendly, making it suitable for environments with a mix of legacy and new implementations. It includes mechanisms to provide information about the target certificate's signature algorithm, public key algorithm and the location of the secondary X.509 certificate, empowering relying parties to make informed decisions on whether to fetch the Secondary Certificate.

The primary motivation for this method is to address the limitations of traditional certificate management approaches, which often lack flexibility, scalability, and seamless update capabilities. By leveraging this mechanism, subscribers can achieve cryptographic agility by facilitating the transition between different algorithms or X.509 certificate types. Operational redundancy is enhanced by enabling the use of backup certificates and minimizing the impact of Primary Certificate expiration or CA infrastructure failures.

The approach ensures backward compatibility with existing systems and leverages established mechanisms, such as the subjectInfoAccess extension, to enable seamless integration.

--- middle

# Introduction

The efficient discovery of X.509 certificates play a critical role in modern cryptographic systems. Traditional certificate management approaches often face challenges in terms of flexibility, scalability, and seamless updates. To address these limitations, this document proposes a novel approach to certificate discovery utilizing the Subject Information Access extension within X.509 certificates.

The primary objective of this approach is to enable efficient multi-certificate handling in protocols, offering several key benefits. First, it enhances cryptographic agility by facilitating smooth transitions between different algorithms or X.509 certificate types. This is particularly valuable in scenarios where subscribers need to upgrade their cryptographic algorithms or adopt new certificate types while maintaining backward compatibility with existing systems.

Second, the proposed method improves operational availability by introducing redundancy in certificate usage. It enables the use of secondary certificates that can serve as backups, ensuring seamless continuity of services even in the event of Primary Certificate expiration or disruptions in the CA infrastructure.

Finally, the approach accommodates multi-key/certificate usage, allowing for a relying party to obtain certificates to perform cryptographic operations that are not certified by a single certificate.

The proposed method is designed to maximize compatibility with existing systems, including legacy implementations. It leverages the subjectInfoAccess extension, which is already established in X.509 certificates, and does not require modifications to the referring certificates. This ensures ease of adoption and avoids disruptions to current certificate management practices.

The following sections outline the details of the proposed approach, including the structure of the SIA extension, the modes of operation, and the considerations for secure implementation and deployment.

By leveraging the capabilities of the SIA extension for certificate discovery, organizations can enhance cryptographic agility, improve operational availability, and accommodate complex multi-key/certificate scenarios, leading to more secure and resilient cryptographic systems.

## Use Case 1: Algorithm Agility

The first use case is improving algorithm agility. For example, the Primary Certificate uses a widely adopted cryptographic algorithm while the Secondary Certificate uses the algorithm that is new and not widely adopted yet. The relying party will be presented with the opportunity to try the new algorithms and certificate types. This will be particularly useful when transitioning from one algorithm to another or to a new certificate/credential type.

In addition, the server may look at the logs to determine how ready the client side is to shift to completely rollover to the new algorithm. This allows the subscriber to gather the metrics necessary to make an informed decision on the best timing to do an algorithm rollover without relying on third parties or security researchers. This is particularly useful for PKIs that have a wide array of client software and requires careful consideration.

## Use Case 2: Operational Redundancy

The second use case is where the Primary and Secondary Certificate adopts the same cryptographic algorithms but for instance, uses certificates issued by two different CAs or two certificates that have different validity periods. The Secondary Certificate may be used as a backup certificate in case the Primary Certificate validity is about to expire.

A common issue is when the intermediate CA certificate expires, and the subscriber forgets to update the intermediate CA configured on the server. Similar to when some software collects the parent certificate through authorityInfoAccess CA Issuer access method when the intermediate certificate is absent, the peer certificate can be obtained.

Due to increased adoption of the ACME protocol, the burden of maintaining the availability of a service is shifted to the CA issuance infrastructure and the availability would be dependent on the CA infrastructure. To increase the operational redundancy, this mechanism can be used to point to another set of certificates that are independent from the Primary Certificate to minimize the chance of a failed transaction.

## Use Case 3: Dual Use

The third use case is where one certificate is used by the named subject for a particular cryptographic operation and a relying party wishes to obtain the public key of the named subject for a different cryptographic operation. For example, the recipient of an email message which was signed using a key that is certified by a single use signing S/MIME certificate may wish to send an encrypted email to the sender. In this case, the recipient will need the sender's public key used for encryption. A pointer to the named subject's encryption certificate will permit the recipient to send an encrypted reply.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Definitions

For conciseness, this section defines several terms that are frequently used throughout this specification.

Primary Certificate: The X.509 certificate that has the subjectInfoAccess extension with the certDiscovery accessMethod pointing to a Secondary Certificate.

Secondary Certificate: The X.509 certificate that is referenced by the Primary Certificate in the subjectInfoAccess extension certDiscovery accessMethod. This certificate may also have a reference to the Primary Certificate in the
subjectInfoAccess extension.

# Certificate Discovery Access Method

This document specifies the new certDiscovery access method for X.509 Subject Information Access (SIA) extension defined in {{!RFC5280}}.

The syntax of subject information access extension syntax is repeated here for convenience:

~~~
   SubjectInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }
~~~

This document defines a new access method `id-ad-certDiscovery` which is an OBJECT IDENTIFIER that indicates the `accessMethod` is for certificate discovery.

~~~
id-ad-certDiscovery OBJECT IDENTIFIER ::= { id-ad TBD }
~~~

The 'accessLocation' is a GeneralName otherName type as defined in [RFC5280]. Recall that the otherName type is defined as `AnotherName`:

~~~
AnotherName ::= SEQUENCE {
     type-id    OBJECT IDENTIFIER,
     value      [0] EXPLICIT ANY DEFINED BY type-id }
~~~

This document defines the `RelatedCertificateDescriptor` type and its corresponding identifier as follows:

~~~
-- Other Name OID Arc --
id-on OBJECT IDENTIFIER ::= { id-pkix 8 }

-- Certificate Discovery Access Descriptor --
id-on-relatedCertificateDescriptor OBJECT IDENTIFIER ::= { id-on TBD }

on-RelatedCertificateDescriptor OTHER-NAME ::= {
      RelatedCertificateDescriptor IDENTIFIED BY id-on-relatedCertificateDescriptor
   }
~~~

When the `accessMethod` has a value of `id-ad-certDiscovery`, then the `accessLocation` MUST contain an `otherName` whose `type-id` is `id-on-relatedCertificateDescriptor` and the `value` is `RelatedCertificateDescriptor`.

`RelatedCertificateDescriptor` is defined as follows:

~~~
 RelatedCertificateDescriptor ::= SEQUENCE {
   method CertDiscoveryMethod,
   intent DiscoveryIntentId OPTIONAL,
   signatureAlgorithm [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
   publicKeyAlgorithm [1] IMPLICIT AlgorithmIdentifier OPTIONAL,
   spkiBinding [2] IMPLICIT SPKIBinding OPTIONAL
}
~~~

`RelatedCertificateDescriptor` is composed of 5 components which are defined below.

## CertDiscoveryMethod

`CertDiscoveryMethod` is defined by the following:

~~~
CertDiscoveryMethod ::= CHOICE {
  byUri [0] IMPLICIT CertLocation
  byInclusion Certificate,
  byLocalPolicy NULL
}
~~~

`CertDiscoveryMethod` is the only required field of `RelatedCertificateDescriptor`. It describes how the related certificate can be retrieved.

There are three methods:

1. The `byUri` method provides a location where the related certificate can be retrieved. The syntax of `CertLocation` is described below.
2. The `byInclusion` method encodes the DER encoding of the related certificate directly.
3. The `byLocalPolicy` method signals that the related certificate is available in a repository that is usable by the application consuming the certificate.

## CertLocation

`CertLocation` is defined by the following:

~~~
CertLocation ::= SEQUENCE {
   uri IA5String,
   certHash [0] IMPLICIT CertHash OPTIONAL
}
~~~

The certificate is referenced by an IA5String that contains the URI of the Secondary Certificate. The DER encoding of the Secondary Certificate MUST be available at the specified location.

`CertLocation` MAY include an optional `certHash` value which can be used to include a cryptographic hash of the DER Encoded Secondary Certificate. The syntax of `CertHash` is described below.

## CertHash {#certhash}

`CertHash` is defined by the following:

~~~~
CertHash ::= SEQUENCE {
   value OCTET STRING,
   -- TODO Add IssuerAndSerialNumber?
   hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm sha-256}
}
~~~~

`certHash` is defined as a SEQUENCE containing the OCTET STRING `value` which is the hash of the DER Encoded reference certificate as well as the `hashAlgorithm`, which contains the AlgorithmIdentifier for the chosen Hash value. All implementations MUST support SHA-256 via `id-sha256`, and other hash functions MAY be supported.

## DiscoveryIntentId

`DiscoveryIntentId` provides optional information to describe the intent of including the discovery information for the related certificate.

Currently, the following intent identifiers are defined:

~~~
 -- Intent OBJECT IDENTIFIER
id-rcd-agility OBJECT IDENTIFIER ::=
                               {id-rcd 1}

id-rcd-redundancy OBJECT IDENTIFIER ::=
                               {id-rcd 2}

id-rcd-dual OBJECT IDENTIFIER ::=
                               {id-rcd 3}

id-rcd-priv-key-stmt OBJECT IDENTIFIER ::=
                               {id-rcd 4}

id-rcd-self OBJECT IDENTIFIER ::=
                               {id-rcd 5}

id-rcd-mandatory OBJECT IDENTIFIER ::=
                               {id-rcd 6}
~~~

### Algorithm Agility

This intent indicates the referenced certificate's intent is to provide algorithm agility; i.e. the two certificates will use different cryptographic algorithms for the same key operations. The two certificates SHOULD be equivalent except for cryptographic algorithm; i.e. the key usages SHOULD match.

### Redundancy

This intent indicates the referenced certificate's intent is to provide operational redundancy; i.e. the Secondary Certificate could be issued by a different CA or has a different validity period which can be used as a backup if the Primary set of certificates is about to expire.


### Dual Usage

This intent indicates the referenced certificate's intent is for dual usage; i.e. the related certificates belong to the same entity and one provides a signing-type key while the other provides an encryption-type key. The two certificates MUST describe the same entity and therefore SHOULD have matching Subject DN and SAN values.

### Statement of Possession of a Private Key

This intent indicates that the Primary Certificate did not not do a full proof-of-possession at enrollment time, but instead it provided a statement of possession as per {{!I-D.ietf-lamps-private-key-stmt-attr}} signed by the Secondary Certificate.

The reason for carrying a RelatedCertificateDescriptor of this type is to track that the Primary Certificate had a trust dependency on the Secondary Certificate at the time of issuance and that presumably the two private keys are co-located on the same key storage. Therefore if one certificate is revoked, they SHOULD both be revoked.

### Self reference

This intent indicates the Uniform Resource Identifier where this certificate is located. Applications which retrieve this certificate can then compare the retrieved certificate with this value to ensure that the correct certificate was retrieved.

This intent can be used to bind the subjects of Primary and Secondary Certificates. The Primary Certificate contains a self-reference to its location, as well as a reference to the Secondary Certificate. The Secondary Certificate contains a self-reference to its location, and a reference to the Primary Certificate. Provided that policy requires subject equivalence when this mechanism is used, then the consuming application can treat both certificates as certifying the same entity.

### Mandatory Binding

This intent indicates that the `RelatedCertificateDescriptor` carries a mandatory binding constraint. When the `intent` is `id-rcd-mandatory`, the consuming application MUST verify the `spkiBinding` field as described in {{spki-binding}}. If the `spkiBinding` field is absent, or if its verification fails, the consuming application MUST reject the `RelatedCertificateDescriptor` and MUST NOT use the Secondary Certificate.

This intent is designed for high-assurance environments such as secure boot, code signing, and IoT device identity, where the secondary certificate is a security requirement rather than a discovery convenience. In these environments, the descriptor acts as a mandatory constraint: if the verifier's policy requires a secondary key and the binding is absent or invalid, the entire certificate chain MUST be rejected.

~~~
id-rcd-mandatory OBJECT IDENTIFIER ::=
                               {id-rcd 6}
~~~

## Signature Algorithm and Public Key Algorithm fields

The signatureAlgorithm is used to indicate the signature algorithm used in the Secondary Certificate and is an optional field. The publicKeyAlgorithm indicates the public key algorithm used in the Secondary Certificate and is an optional field.

When the validation of the Primary Certificate fails, the software that understands the SIA extension and the certDiscovery access method uses the information to determine whether to fetch the Secondary Certificate. The software will look at the signatureAlgorithm and publicKeyAlgorithm to determine whether the Secondary Certificate has the signature algorithm and certificate public key algorithm it can process. If the software understands the signature algorithm and certificate public key algorithm, the software fetches the certificate from the URI specified in the relatedCertificateLocation and attempts another validation. Otherwise, the validation simply fails.

## SPKI Binding {#spki-binding}

The `spkiBinding` field provides an OPTIONAL cryptographic binding between the Primary and Secondary Certificates using hashes of their `subjectPublicKeyInfo` (SPKI) fields. This binding serves two purposes: it prevents descriptor transplantation (where a `RelatedCertificateDescriptor` is moved from one certificate to another) and it enables bidirectional binding between certificate pairs.

Since both public keys are known before either certificate is signed, binding by SPKI hash avoids the circular dependency that would arise from binding by full certificate hash. Both H(Primary.SPKI) and H(Secondary.SPKI) can be computed and embedded in both certificates' descriptors before either TBS is assembled.

`SPKIBinding` is defined as follows:

~~~
SPKIBinding ::= SEQUENCE {
    hostSPKIHash CertHash,
    relatedSPKIHash CertHash OPTIONAL
}
~~~

The `SPKIBinding` type contains two components:

1. `hostSPKIHash`: A `CertHash` containing the hash of the DER-encoded `subjectPublicKeyInfo` field of the certificate that contains this `RelatedCertificateDescriptor`. This field is REQUIRED when `spkiBinding` is present. It prevents descriptor transplantation: if the descriptor is moved to a different certificate, the `hostSPKIHash` will not match the hosting certificate's SPKI and the verifier MUST reject the descriptor.

2. `relatedSPKIHash`: An OPTIONAL `CertHash` containing the hash of the DER-encoded `subjectPublicKeyInfo` field of the related (Secondary) certificate. When present, this field identifies the specific Secondary Certificate. When both certificates include descriptors with both `hostSPKIHash` and `relatedSPKIHash` pointing to each other, the binding is bidirectional.

The `CertHash` type, defined in {{certhash}}, is reused for both components. All implementations MUST support SHA-256 (`id-sha256`) for SPKI hash computation.

### Verification Procedure {#spki-verification}

When a verifier processes a `RelatedCertificateDescriptor` that contains an `spkiBinding`, the verifier MUST perform the following steps:

1. Compute the hash of the DER-encoded `subjectPublicKeyInfo` of the certificate containing the descriptor (the Primary Certificate), using the hash algorithm specified in `hostSPKIHash.hashAlgorithm`.

2. Compare the computed hash with `hostSPKIHash.value`. If the values do not match, the verifier MUST reject the `RelatedCertificateDescriptor`. A mismatch indicates that the descriptor has been transplanted from another certificate.

3. If `relatedSPKIHash` is present and the Secondary Certificate has been obtained, the verifier MUST compute the hash of the DER-encoded `subjectPublicKeyInfo` of the Secondary Certificate using the hash algorithm specified in `relatedSPKIHash.hashAlgorithm`, and compare the result with `relatedSPKIHash.value`. If the values do not match, the verifier MUST reject the Secondary Certificate.

For bidirectional binding, both the Primary and Secondary Certificates contain `RelatedCertificateDescriptor`s pointing to each other, each with `hostSPKIHash` and `relatedSPKIHash`. The verifier performs the above procedure on both descriptors independently.

If the verifier does not support the hash algorithm specified in `hostSPKIHash.hashAlgorithm` or `relatedSPKIHash.hashAlgorithm`, the verifier MUST treat the binding as unverifiable. If the verifier's local policy requires binding verification (or the `intent` is `id-rcd-mandatory`), the verifier MUST reject the descriptor.

# Security Considerations

Retrieval of the Secondary Certificate is not sufficient to consider the Secondary Certificate trustworthy. The certification path validation algorithm as defined in section 6 of {{RFC5280}} MUST be performed for the Secondary Certificate.

The use of the self-reference intent can be used to provide a subject binding between the Primary and Secondary Certificates. However, the procedure for validating subject equivalence MUST be defined by policy. As a result, validation of
subject equivalence is out of scope of this document.

The Secondary Certificate may also have the certDiscovery access method. In order to avoid cyclic loops or infinite chaining, the validator should be mindful of how many fetching attempts it allows in one validation.

The same security considerations for `caIssuers` access method outlined in {{RFC5280}} applies to the certDiscovery access method. In order to avoid recursive certificate validations which involve online revocation checking, untrusted transport protocols (such as plaintext HTTP) are commonly used for serving certificate files. While the use of such protocols avoids issues with recursive certification path validations and associated online revocation checking, it also enables an attacker to tamper with data and perform substitution attacks. Clients fetching certificates using the mechanism specified in this document MUST treat downloaded certificate data as untrusted and perform requisite checks to ensure that the downloaded data is not malicious.

## Descriptor Transplantation

Without `hostSPKIHash`, an attacker who possesses two valid certificates from the same CA — CertA and CertB (with different keys) — could transplant CertA's `RelatedCertificateDescriptor` onto CertB by obtaining a re-issued CertB that contains CertA's descriptor. A verifier would then associate the secondary identity with CertB's key, which the attacker may control.

The `hostSPKIHash` field in `SPKIBinding` prevents this attack. The descriptor contains a hash of CertA's `subjectPublicKeyInfo`. When the descriptor is transplanted to CertB, the verifier computes the hash of CertB's `subjectPublicKeyInfo`, detects the mismatch, and rejects the descriptor. The binding is non-fungible — it cannot be moved between certificates without detection.

## Descriptor Stripping

An attacker who controls the certificate delivery channel (e.g., a TLS middlebox or a compromised firmware delivery pipeline) could strip the `subjectInfoAccess` extension entirely, forcing the verifier to accept only the Primary Certificate.

For standard PKI use cases, this is acceptable — the Primary Certificate remains independently valid. For high-assurance profiles where the secondary key is a security requirement (e.g., post-quantum algorithm adoption in secure boot, threshold signing for firmware verification), stripping constitutes a downgrade attack.

The `id-rcd-mandatory` intent identifier addresses this: when a verifier's local policy requires a secondary key and the descriptor is absent, the verifier MUST reject the certificate chain. This converts stripping from an invisible downgrade into a detectable failure.

## SPKI Binding and Circular Dependencies

A natural alternative to SPKI binding is full certificate binding: include H(Secondary Certificate) in the Primary and H(Primary Certificate) in the Secondary. This creates a circular dependency — the hash of CertA depends on the contents of CertA, which includes the hash of CertB, which depends on the contents of CertB, which includes the hash of CertA. Neither certificate can be signed first.

The existing `certHash` in `CertLocation` avoids this by being unidirectional: only the Primary includes H(Secondary). This is sufficient for discovery verification after fetching, but does not provide bidirectional binding.

SPKI binding resolves the circularity because `subjectPublicKeyInfo` is determined before signing. Both public keys are generated before either certificate's TBSCertificate is assembled. Therefore H(Primary.SPKI) and H(Secondary.SPKI) can be computed and embedded in both certificates' descriptors without creating a dependency cycle.

## SPKI Binding Hash Algorithm Agility

The `CertHash` type used for SPKI binding includes a `hashAlgorithm` field, providing algorithm agility. All implementations MUST support SHA-256 (`id-sha256`). For environments requiring post-quantum hash resilience, SHA-3 (`id-sha3-256`) or SHAKE256 MAY be used. The hash algorithm for SPKI binding is independent of the certificate's signature algorithm — a certificate signed with ML-DSA can use SHA-256 for its SPKI binding.

## Multi-Hop Chains with SPKI Binding

In a certificate chain with multiple levels carrying descriptors (e.g., Root, Intermediate, and Leaf certificates each carrying a `RelatedCertificateDescriptor`), each descriptor's `spkiBinding` is verified independently at its own level. The binding at level N does not depend on the binding at level N-1. This ensures that compromise or removal of a descriptor at one level does not affect binding integrity at other levels.

Verifiers processing multi-hop chains SHOULD verify all descriptors in the chain before accepting the secondary trust path. This ensures the security policy is enforced from the leaf back to the root.

# IANA Considerations

## Module Identifier

IANA is requested to add the following entry in the "SMI Security for PKIX Module Identifier" registry, defined by [RFC7299]:

| Decimal | Description          | References |
| ------- | -------------------- | ---------- |
| TBD1    | id-mod-CertDiscovery | [this-RFC] |

## Access Descriptor

IANA is requested to add the following entry in the "SMI Security for PKIX Access Descriptor" registry, defined by [RFC7299]:

| Decimal | Description          | References |
| ------- | -------------------- | ---------- |
| TBD2    | id-ad-certDiscovery  | [this-RFC] |

## Other Name Form

IANA is requested to add the following entry in the "SMI Security for PKIX Access Descriptor" registry, defined by [RFC7299]:

| Decimal | Description                        | References |
| ------- | ---------------------------------- | ---------- |
| TBD3    | id-on-relatedCertificateDescriptor | [this-RFC] |

## Certificate Discovery Intent Identifiers

To allocate id-rcd, this document introduces a new PKIX OID arc for certificate discovery intent identifiers:

IANA is requested to add the following entry to "SMI Security for PKIX" registry, defined by [RFC 7299]:

| Decimal | Description | References |
| ------- | ----------- | ---------- |
| TBD4    | Certificate Discovery Intent Identifier | [this-RFC] |

IANA is requested to create the "Certificate Discovery Intent Identifiers" registry with the following initial values:

| Decimal | Description          | References |
| ------- | -------------------- | ---------- |
| 1       | id-rcd-agility       | [this-RFC] |
| 2       | id-rcd-redundanc     | [this-RFC] |
| 3       | id-rcd-dual          | [this-RFC] |
| 3       | id-rcd-priv-key-stmt | [this-RFC] |
| 5       | id-rcd-self          | [this-RFC] |
| 6       | id-rcd-mandatory     | [this-RFC] |

Updates to this table are to be made according to the Specification Required policy as defined in [RFC8126].

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

# Appendix A. ASN.1 Module
{:numbered="false"}

The following ASN.1 module provides the complete definition of the Certificate Discovery access descriptor.

~~~
CertDiscovery { iso(1) identified-organization(3) dod(6) internet(1)
   security(5) mechanisms(5) pkix(7) id-mod(0) id-mod-CertDiscovery(TBD) }

   DEFINITIONS EXPLICIT TAGS ::=

   BEGIN

-- EXPORTS ALL --

   IMPORTS
    OTHER-NAME, AlgorithmIdentifier, Certificate
    FROM PKIX1Implicit-2009
      { iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-implicit-02(59) }

    id-pkix, id-ad
    FROM PKIX1Explicit-2009
      { iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-explicit-02(51) } ;

   id-ad-certDiscovery OBJECT IDENTIFIER ::= { id-ad TBD2 }

   -- Other Name OID Arc --

   id-on OBJECT IDENTIFIER ::= { id-pkix 8 }

   -- Certificate Discovery Access Descriptor --

   id-on-relatedCertificateDescriptor OBJECT IDENTIFIER ::= { id-on TBD3 }

   on-RelatedCertificateDescriptor OTHER-NAME ::= {
      RelatedCertificateDescriptor IDENTIFIED BY id-on-relatedCertificateDescriptor
   }

   id-rcd OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-rcd(TBD4) }

   -- Intent OBJECT IDENTIFIERs

   DiscoveryIntentId ::= OBJECT IDENTIFIER

   id-rcd-agility DisoveryIntentId ::= {id-rcd 1}
   id-rcd-redundency DisoveryIntentId ::= {id-rcd 2}
   id-rcd-dual DisoveryIntentId ::= {id-rcd 3}
   id-rcd-priv-key-stmt DisoveryIntentId ::= {id-rcd 4}
   id-rcd-self DisoveryIntentId ::= {id-rcd 5}
   id-rcd-mandatory DisoveryIntentId ::= {id-rcd 6}


   RelatedCertificateDescriptor ::= SEQUENCE {
     method CertDiscoveryMethod,
     intent DiscoveryIntentId OPTIONAL,
     signatureAlgorithm [0] IMPLICIT AlgorithmIdentifier OPTIONAL,
     publicKeyAlgorithm [1] IMPLICIT AlgorithmIdentifier OPTIONAL,
     spkiBinding [2] IMPLICIT SPKIBinding OPTIONAL
   }

   SPKIBinding ::= SEQUENCE {
     hostSPKIHash CertHash,
     relatedSPKIHash CertHash OPTIONAL
   }

   CertDiscoveryMethod ::= CHOICE {
     byUri [0] IMPLICIT CertLocation,
     byInclusion Certificate,
     byLocalPolicy NULL
   }

   CertLocation ::= SEQUENCE {
      uri IA5String,
      certHash [0] IMPLICIT CertHash OPTIONAL
   }

   CertHash ::= SEQUENCE {
      value OCTET STRING,
      hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm sha-256}
   }

   END
~~~

