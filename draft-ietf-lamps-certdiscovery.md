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
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "tomofumiokubo/certificatediscovery"
  latest: "https://tomofumiokubo.github.io/certificatediscovery/draft-ietf-lamps-certdiscovery.html"

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

This document specifies a method to discover a secondary X.509 certificate associated with an X.509 certificate to enable efficient multi-certificate handling in protocols. The objective is threefold: to enhance cryptographic agility, improve operational availability, and accommodate multi-key/certificate usage. The proposed method aims to maximize compatibility with existing systems and is designed to be legacy-friendly, making it suitable for environments with a mix of legacy and new implementations. It includes mechanisms to provide information about the target certificate's signature algorithm, public key algorithm and the location of the secondary X.509 certificate, empowering relying parties to make informed decisions on whether or not to fetch the secondary certificate.

The primary motivation for this method is to address the limitations of traditional certificate management approaches, which often lack flexibility, scalability, and seamless update capabilities. By leveraging this mechanism, subscribers can achieve cryptographic agility by facilitating the transition between different algorithms or X.509 certificate types. Operational redundancy is enhanced by enabling the use of backup certificates and minimizing the impact of primary certificate expiration or CA infrastructure failures.

The approach ensures backward compatibility with existing systems and leverages established mechanisms, such as the subjectInfoAccess extension, to enable seamless integration. It does not focus on identity assurance between the primary and secondary certificates, deferring such considerations to complementary mechanisms.


--- middle

# Introduction

The efficient discovery of X.509 certificates play a critical role in modern cryptographic systems. Traditional certificate management approaches often face challenges in terms of flexibility, scalability, and seamless updates. To address these limitations, this document proposes a novel approach to certificate discovery utilizing the Subject Information Access extension within X.509 certificates.

The primary objective of this approach is to enable efficient multi-certificate handling in protocols, offering several key benefits. First, it enhances cryptographic agility by facilitating smooth transitions between different algorithms or X.509 certificate types. This is particularly valuable in scenarios where subscribers need to upgrade their cryptographic algorithms or adopt new certificate types while maintaining backward compatibility with existing systems.

Second, the proposed method improves operational availability by introducing redundancy in certificate usage. It enables the use of secondary certificates that can serve as backups, ensuring seamless continuity of services even in the event of primary certificate expiration or disruptions in the CA infrastructure.

Finally, the approach accommodates multi-key/certificate usage, allowing for a relying party to obtain certificates to perform cryptographic operations that are not certified by a single certificate.

The proposed method is designed to maximize compatibility with existing systems, including legacy implementations. It leverages the SIA extension, which is already established in X.509 certificates, and does not require modifications to the referring certificates. This ensures ease of adoption and avoids disruptions to current certificate management practices.

It's important to note that this specification does not aim to solve or assure the identity (subject) binding between the primary and secondary certificates. Instead, it focuses on providing a mechanism for efficient certificate discovery, while identity assurance can be addressed through complementary mechanisms such as draft-becker-guthrie-cert-binding-for-multi-auth-02.

In the following sections, we will outline the details of the proposed approach, including the structure of the SIA extension, the modes of operation, and the considerations for secure implementation and deployment.

By leveraging the capabilities of the SIA extension for certificate discovery, organizations can enhance cryptographic agility, improve operational availability, and accommodate complex multi-key/certificate scenarios, leading to more secure and resilient cryptographic systems.

## Use Case 1: Algorithm Agility

The first use case is improving algorithm agility. For example, the Primary Certificate uses a widely adopted cryptographic algorithm while the Secondary Certificate uses the algorithm that is new and not widely adopted yet. The relying party will be presented with the opportunity to try the new algorithms and certificate types. This will be particularly useful when transitioning from one algorithm to another or to a new certificate/credential type.

In addition, the server may look at the logs to determine how ready the client side is to shift to completely rollover to the new algorithm. This allows the subscriber to gather the metrics necessary to make an informed decision on the best timing to do an algorithm rollover without relying on third parties or security researchers. This is particularly useful for PKIs that have a wide array of client software and requires careful considerations.

## Use Case 2: Operational Redundancy

The second use case is where the Primary and Secondary Certificate adopts the same cryptographic algorithms but for instance, uses certificates issued by two different CAs or two certificates that has different validity periods. The Secondary Certificate may be used as a backup certificate in case the Primary Certificate validity is about to expire.

A common issue is when the intermediate CA certificate expires and the subscriber forgets to update the intermediate CA configured on the server. Similar to when some software collects the parent certificate through authorityInfoAccess CA Issuer access method when the intermediate certificate is absent, the peer certificate can be obtained.

Due to increased adoption of the ACME protocol, the burden of maintaining the availability of a service is shifted to the CA issuance infrastructure and the availability would be dependent on the CA infrastructure. To increase the operational redundancy, this mechanism can be used to point to another set of certificates that are independent from the Primary Certificate to minimize the chance of a failed transaction.

## Use Case 3: Dual Use

The third use case is where one certificate is used by the named subject for a particular cryptographic operation and a relying party wishes to obtain the public key of the named subject for a different cryptographic operation. For example, the recipient of an email message which was signed using a key that is certified by a single-use signing S/MIME certificate may wish to send an encrypted email to the sender. In this case, the recipient will need the sender's public key used for encryption. A pointer to the named subject's encryption certificate will permit the recipient to send an encrypted reply.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

## Definitions

For conciseness, this section defines several terms that are frequently used throughout this specification.

Primary Certificate: The X.509 certificate that has the subjectInfoAccess extension with the certDiscovery accessMethod pointing to a Secondary Certificate.

Secondary Certificate: The X.509 certificate that is referenced by the Primary Certificate in the subjectInfoAccess extension certDiscovery accessMethod

# Certificate Discovery Access Method Certificates

This document specifies the new certDiscovery access method for X.509 Subject Information Access (SIA) extension defined in {{!RFC5280}}.
The certDiscovery access method has 3 components. The uniformResourceIdentifier which is an IA5String that has the URL reference to the Secondary Certificate. The signatureAlgorithm which indicates the signature algorithm used in the Secondary Certificate. Finally, the publicKeyAlgorithm which indicates the public key algorithm used in the Secondary Certificate.

When the validation of the Primary Certificate fails, the software that understands the SIA extension and the certDiscovery access method uses the information to determine whether or not to fetch the Secondary Certificate. The software will look at the signatureAlgorithm and publicKeyAlgorithm to determine whether the Secondary Certificate has the signature algorithm and certificate public key algorithm it can process. If the software understands the signature algorithm and certificate public key algorithm, the software fetches the certificate from the URI specified in the relatedCertificateLocation and attempts another validation. Otherwise, the validation simply fails.

The syntax of subject information access extension syntax is repeated here for convenience:

~~~
   SubjectInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }
~~~

The syntax of the related certificate descriptor is as follows:

~~~
   id-ad  OBJECT IDENTIFIER  ::= {
     iso(1) identified-organization(3) dod(6) internet(1)
     security(5) mechanisms(5) pkix(7) ad(48) }
    id-ad-certDiscovery OBJECT IDENTIFIER ::= { id-ad TBD }

   id-on-relatedCertificateDescriptor OBJECT IDENTIFIER ::= { id-on TBD2 }

   on-RelatedCertificateDescriptor OTHER-NAME ::= {
        RelatedCertificateDescriptor IDENTIFIED BY id-on-relatedCertificateDescriptor
    }

   RelatedCertificateDescriptor ::= SEQUENCE {
	   uniformResourceIdentifier IA5String,
	   signatureAlgorithm 	[0] IMPLICIT AlgorithmIdentifier OPTIONAL,
	   publicKeyAlgorithm 	[1] IMPLICIT AlgorithmIdentifier OPTIONAL
   }
~~~

The semantics of other id-ad-certDiscovery accessLocation name forms are not defined.

Note:  For a description of uniformResourceIdentifier consult section 4.2.2.1 of [!RFC5280].

# Security Considerations

This mechanism does not assure the binding of the identity of the subject in the Primary Certificate and the Secondary Certificate. To assure the binding of identities of the two certificates, a confirming CA should adopt a separate mechanism such as draft-becker-guthrie-cert-binding-for-multi-auth-02 for to explicitly express the binding of identities.

There is a chance the Secondary Certificate may also have the certDiscovery access method. In order to avoid cyclic loops or infinite chaining, the validator should be mindful of how many fetching attempts it allows in one validation.

The same security considerations for CAIssuer access method outlined in {{RFC5280}} applies to the certDiscovery access method. In order to avoid recursive certificate validations which involve online revocation checking, untrusted transport protocols (such as plaintext HTTP) are commonly used for serving certificate files. While the use of such protocols avoids issues with recursive certification path validations and associated online revocation checking, it also enables an attacker to tamper with data and perform substitution attacks. Clients fetching certificates using the mechanism specified in this document MUST treat downloaded certificate data as untrusted and perform requisite checks to ensure that the downloaded data is not malicious.

# IANA Considerations

TBD


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

# Appendix A. ASN.1 Module
{:numbered="false"}

The following ASN.1 module provides the complete definition of the Certificate Discovery access descriptor.

~~~
CertDiscovery { iso(1) identified-organization(3) dod(6) internet(1)
   security(5) mechanisms(5) pkix(7) id-mod(0) id-mod-CertDiscovery(TBD1) }

   DEFINITIONS EXPLICIT TAGS ::=

   BEGIN

   -- EXPORTS ALL --

   IMPORTS
    OTHER-NAME
    FROM PKIX1Implicit-2009
      { iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-implicit-02(59) }

    id-pkix, id-ad
    FROM PKIX1Explicit-2009
      { iso(1) identified-organization(3) dod(6) internet(1) security(5)
      mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-explicit-02(51) } ;

   -- Access descriptor OID --

   id-ad-certDiscovery OBJECT IDENTIFIER ::= { id-ad TBD }

   -- Other Name OID Arc --

   id-on OBJECT IDENTIFIER ::= { id-pkix 8 }

   -- Certificate Discovery Access Descriptor --

   id-on-relatedCertificateDescriptor OBJECT IDENTIFIER ::= { id-on TBD2 }

   on-RelatedCertificateDescriptor OTHER-NAME ::= {
        RelatedCertificateDescriptor IDENTIFIED BY id-on-relatedCertificateDescriptor
    }

   RelatedCertificateDescriptor ::= SEQUENCE {
	   uniformResourceIdentifier IA5String,
	   signatureAlgorithm 	[0] IMPLICIT AlgorithmIdentifier OPTIONAL,
	   publicKeyAlgorithm 	[1] IMPLICIT AlgorithmIdentifier OPTIONAL
   }

   END
~~~

