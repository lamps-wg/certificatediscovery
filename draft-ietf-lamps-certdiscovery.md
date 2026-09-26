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

This document specifies a method to discover a referenced X.509 certificate associated with the current X.509 certificate. This enables efficient multi-certificate or fallback certificate handling in protocols. The objective is threefold: to enhance cryptographic agility, improve operational availability, and accommodate multi-key/certificate usage. The proposed method aims to maximize compatibility with existing systems and is designed to be legacy-friendly, making it suitable for environments with a mix of legacy and new implementations. It includes mechanisms to provide a URI from which the referenced X.509 certificate can be retrieved as well as information about the target certificate's signature and public key algorithm, empowering relying parties to make informed decisions on whether to retrieve the Referenced Certificate, and a certificate hash to ensure that the correct certificate was retrieved.

--- middle

# Introduction

Cryptographic agility and fallback often feature prominently in cryptographic migrations, whether it's migrating algorithms, infrastructures, keys, or some other aspect. Discovery is a key aspect of agility -- in this case meaning that an application holding an X.509 certificate for a peer can easily learn about and retrieve alternative versions of the certificate they are holding, a space that is under-served by existing X.509 extensions. To address these limitations, this document proposes a novel approach to certificate discovery utilizing the Subject Information Access extension within X.509 certificates.

The primary objective of this approach is to enable efficient multi-certificate handling in protocols, offering several key benefits. First, it enhances cryptographic agility by facilitating smooth transitions between different algorithms or X.509 certificate types. This is particularly valuable in scenarios where subscribers need to upgrade their cryptographic algorithms or adopt new certificate types while maintaining backward compatibility with existing systems.

Second, the proposed method improves operational availability by introducing redundancy in certificate usage. It enables the automatic discovery and use of Referenced Certificates that can serve as fallbacks, ensuring seamless continuity of services even in the event of expiration or revocation of the Current Certificate, or disruptions in the Certification Authority (CA) infrastructure.

Finally, the approach accommodates multi-key/certificate usage, allowing for a CA to indicate that two (or more) certificates are to be used together.

relying party to obtain certificates to perform cryptographic operations that are not certified by a single certificate.

The proposed method is designed to maximize compatibility with existing systems, including legacy implementations. It leverages the subjectInfoAccess extension, which is already established in X.509 certificates, and does not require modifications to the referring certificates. This ensures ease of adoption and avoids disruptions to current certificate management practices.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Definitions

For conciseness, this section defines several terms that are frequently used throughout this specification.

Current Certificate: the X.509 certificate currently being validated, which contains an subjectInfoAccess extension with the certDiscovery accessMethod pointing to a Referenced Certificate, and may also contain a certDiscoverySelfLocation URI referencing itself.

Referenced Certificate: The X.509 certificate that is referenced by the Current Certificate in the subjectInfoAccess extension certDiscovery accessMethod.

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

This document defines a new `SubjectInfoAccessSyntax` access method `id-ad-certDiscovery` which is an OBJECT IDENTIFIER that indicates the `accessMethod` is for carrying a certificate discovery description of a Referenced Certificate.

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
   signatureAlgorithm [0] AlgorithmIdentifier OPTIONAL,
   publicKeyAlgorithm [1] AlgorithmIdentifier OPTIONAL,
   certHash [2] RelatedCertificate OPTIONAL
}
~~~

A certificate MAY have any number of `RelatedCertificateDescriptor` SIA `AccessDescriptions`.

Each component of the `RelatedCertificateDescriptor` is defined below.

## CertDiscoveryMethod

`CertDiscoveryMethod` describes the method by which the Referenced Certificate
can be retrieved. 

`CertDiscoveryMethod` is defined by the following:

~~~
CertDiscoveryMethod ::= CHOICE {
   byUri IA5String,
   byInclusion Certificate,
   byLocalPolicy NULL,
   byOther [0] INSTANCE OF OTHER-DISCOVERY-METHOD
}
~~~

Depending on the method used, the other optional elements of `RelatedCertificateDescriptor`
can become either mandatory, recommended, or forbidden.

### byUri

The `byUri` method MUST provide a URI formatted according to [!RFC3986] from which the Referenced Certificate can be retrieved.

When the `CertDiscoveryMethod` is `byUri`, the fields `signatureAlgorithm`, `publicKeyAlgorithm`, and `certHash` SHOULD be populated as described below so that an application can decide if the Referenced Certificate is likely to be useful before performing the retrieval. After performing the retrieval, the application MUST check that the populated `signatureAlgorithm`, `publicKeyAlgorithm`, and `certHash` match the retrieved certificate; if any do not match then the retrieval MUST be considered to have failed.

Note that two (or more) certificates can reference each other in cases where the URIs are pre-allocated prior to certificate issuance, and the certificates to be issued as a batch.

To enhance security, the URI SHOULD be cryptographically random and is RECOMMENDED to contain the certificate serial number, although care needs to be taken when publishing the related certificates asynchronously since publication of a first certificate containing the serial number of a not-yet-issued certificate could expose the second certificate to forgery attacks.

### byInclusion

The `byInclusion` method encodes the DER encoding of the Referenced Certificate directly into the Current Certificate. The Referenced Certificate MAY be extract and used directly as a standalone certificate.

When the `CertDiscoveryMethod` is `byInclusion`, the fields `signatureAlgorithm`, `publicKeyAlgorithm`, and `certHash` MUST NOT be populated since the content is already present and would be redundant.

### byLocalPolicy

The `byLocalPolicy` method signals that the related certificate is available in a repository that is available to the application according to its local policy. The details of this method are deliberately left out-of-scope.

When the `CertDiscoveryMethod` is `byLocalPolicy`, at least one of the fields `signatureAlgorithm`, `publicKeyAlgorithm`, or `certHash` MUST be populated.
The application MUST check that the populated `signatureAlgorithm`, `publicKeyAlgorithm`, and `certHash` match the retrieved certificate; if any do not match then the retrieval MUST be considered to have failed.

### byOther

The `byOther` method acts as an extensibility point for adding additional methods in the future.
A new `byOther` method MUST by accompanied by a specification of its wire format and interaction 
with the `signatureAlgorithm`, `publicKeyAlgorithm`, and `certHash` fields of `RelatedCertificateDescriptor`.

## Signature Algorithm and Public Key Algorithm fields

The `signatureAlgorithm` and `publicKeyAlgorithm` is to allow an application that has rejected the Current Certificate because either the signature or public key algorithm is unrecognized or violates its policy to instead retrieve an acceptable Referenced Certificate.

If present, the `signatureAlgorithm` MUST match the `signatureAlgorithm` field in the Referenced Certificate.

If present, the `publicKeyAlgorithm` MUST match the `subjectPublicKeyInfo.algorithm` field in the Referenced Certificate.


## certHash

The `certHash` field is intended primarily as a lookup value for finding the referenced certificate in a repository indexed by certificate hash. When present, it SHOULD also be used to confirm that the correct certificate was retrieved by hashing the retrieved certificate and comparing the hash value. However, it SHOULD NOT be considered a security mechanism because, by itself, it does not convey any intention about why or for what purpose the two certificates are related.

The `certHash` field uses the `RelatedCertificate` structure, which is defined in [!RFC9763] and simply contains the hash of a certificate.
Recall its definition:

~~~
RelatedCertificate ::= SEQUENCE {
  hashAlgorithm DigestAlgorithmIdentifier,
  hashValue     OCTET STRING }
~~~

Its semantics mirror those specified in [!RFC9763], repeated here for convenience.

The `hashAlgorithm` field identifies the hash algorithm used to compute hashValue, which is the digest value obtained from hashing the entire Referenced Certificate.
If there is a hash algorithm explicitly indicated by the related certificate's signature OID (e.g., ecdsa-with-SHA512), that hash algorithm SHOULD also be used here.

Note that, unlike the `byUri` method, it is not possible to bi-directionally link two (or more) certificates via the `certHash` field.


# Certificate Discovery Self Location Access Method

This document defines a new `SubjectInfoAccessSyntax` access method `id-ad-certDiscoverySelfLocation` which is an OBJECT IDENTIFIER that indicates the `accessMethod` is for carrying a certificate discovery self-reference.
In other words, a certificate MAY carry its own URI as a way to further enhance discoverability and validate that the correct certificate was retrieved.

~~~
id-ad-certDiscoverySelfLocation OBJECT IDENTIFIER ::= { id-ad TBD4 }
~~~

The SubjectInfoAccessSyntax AccessDescription accessLocation MUST carry a GeneralName uniformResourceIdentifier.

This access method indicates the URI [!RFC3986] where the Current Certificate is located. Applications which have retrieved this certificate using a `byUri` method SHOULD extract this value from the retrieved certificate confirm that the correct certificate was retrieved.

A certificate MAY have any number of `certDiscoverySelfLocation` SIA `AccessDescriptions`.

# Expired, Revoked, or Untrusted Current Certificate

In the case that the Current Certificate is unusable, for example because it is expired, revoked, does not chain to a trusted root, or for any other reason, the application MAY still follow the `RelatedCertificateDescriptor` to see if this yields a valid and usable certificate.

This provides great flexibility in error-recovery scenarios. In addition, this will allow for more pro-active migration to new infrastructures, knowing that applications will be able to follow `RelatedCertificateDescriptor`s to their preferred version of the certificate.

Since this is merely a mechanism for discovering the existence of the Referenced Certificate, doing so from an untrusted certificate does not pose security issues.


# Security Considerations

Retrieval of the Referenced Certificate is not sufficient to consider the Referenced Certificate trustworthy. The certification path validation algorithm as defined in section 6 of {{RFC5280}} MUST be performed for the Referenced Certificate. A reference from a `RelatedCertificateDescriptor`, even in the presence of a `certHash` does not imply any form of endorsement or hierarchical relationship between the two certificates unless the mechanism in this draft is augmented with additional X.509v3 extensions or policies that specify those semantics.

The use of the self-reference can be used to provide a subject binding between the Current and Referenced Certificates even if their other data such as subject name or public key do not match. However, the procedure for validating subject equivalence MUST be defined by policy and be consistent with the policies of the issuing CA. As a result, validation of subject equivalence is out of scope of this document.

The Referenced Certificate may also have a certDiscovery access method. In order to avoid cyclic loops or infinite chaining, leading to denial-of-service scenarios, the validator SHOULD employ a maximum depth or cycle-detection algorithm.

The same security considerations for `caIssuers` access method outlined in {{RFC5280}} applies to the certDiscovery access method. In order to avoid recursive certificate validations which involve online revocation checking, untrusted transport protocols (such as plaintext HTTP) are commonly used for serving certificate files. While the use of such protocols avoids issues with recursive certification path validations and associated online revocation checking, it also enables an attacker to tamper with data and perform substitution attacks. Applications retrieving certificates using the mechanism specified in this document MUST treat downloaded certificate data as untrusted and perform requisite checks to ensure that the downloaded data is not malicious.

Typically, it is unsafe to use any content from a certificate that is expired, revoked, or whose signature cannot be validated. The `RelatedCertificateDescriptor` extension is an exception to this rule since it is intended to bridge across these exact types of failure scenarios and is merely making the application aware of the existence of a Referenced Certificate. Once retrieved, the Referenced Certificate SHOULD be validated independently as if it had been provided as the Current. That said, applications MAY refuse to retrieve URIs from an untrusted, or, to a lesser extent, revoked certificate. In most cases, a `RelatedCertificateDescriptor` URI asserted by the CA at issuance time will remain valid for the lifetime of the certificate, unless of course an incorrect URI is the reason for revocation, or the certificate was forged by a malicious actor for the explicit purpose of getting a victim application to fetch the malicious URI.

This specification does not provide a mechanism for identifying the purpose of the cross-reference between certificates. The implied purpose is fallback redundancy. If the purpose is security-related, for example a pair of certificates are only to be used together in a two-certificate protocol, or their revocation status is intertwined as is the case when a signing certificate signs a Certificate Signing Request (CSR) for an encryption certificate, then the CA SHOULD add an additional extension or policy OID to the certificates to further constrain verifier handling.

To enhance security, the URI SHOULD be cryptographically random and is RECOMMENDED to contain the certificate serial number, although care needs to be taken when publishing the related certificates asynchronously since publication of a first certificate containing the serial number of a not-yet-issued certificate could expose the second certificate to forgery attacks.

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
| TBD4    | id-ad-certDiscoverySelfLocation | [this-RFC] |

## Other Name Form

IANA is requested to add the following entry in the "SMI Security for PKIX Access Descriptor" registry, defined by [RFC7299]:

| Decimal | Description                        | References |
| ------- | ---------------------------------- | ---------- |
| TBD3    | id-on-relatedCertificateDescriptor | [this-RFC] |

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
      mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-explicit-02(51) }

    RelatedCertificate
    FROM RelatedCertificate
      { iso(1) identified-organization(3) dod(6)
       internet(1) security(5) mechanisms(5) pkix(7) id-mod(0)
     id-mod-related-cert-2023(115)} ;

   id-ad-certDiscovery OBJECT IDENTIFIER ::= { id-ad TBD2 }

   -- Other Name OID Arc --

   id-on OBJECT IDENTIFIER ::= { id-pkix 8 }

   -- Certificate Discovery Access Descriptor --

   id-on-relatedCertificateDescriptor OBJECT IDENTIFIER ::= { id-on TBD3 }

   -- Always encode as a GeneralName uniform resource identifier (URI)
   id-ad-certDiscoverySelfLocation OBJECT IDENTIFIER ::= { id-ad TBD4 }

   on-RelatedCertificateDescriptor OTHER-NAME ::= {
      RelatedCertificateDescriptor IDENTIFIED BY id-on-relatedCertificateDescriptor
   }

   id-rcd OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-rcd(60) }

   RelatedCertificateDescriptor ::= SEQUENCE {
     method CertDiscoveryMethod,
     signatureAlgorithm [0] AlgorithmIdentifier OPTIONAL,
     publicKeyAlgorithm [1] AlgorithmIdentifier OPTIONAL,
     certHash [2] RelatedCertificate OPTIONAL
   }

   -- RelatedCertificate is defined in RFC 9763

   CertDiscoveryMethod ::= CHOICE {
     byUri IA5String,
     byInclusion Certificate,
     byLocalPolicy NULL,
     byOther [0] INSTANCE OF OTHER-DISCOVERY-METHOD
   }

   OTHER-DISCOVERY-METHOD ::= TYPE-IDENTIFIER

   END
~~~
