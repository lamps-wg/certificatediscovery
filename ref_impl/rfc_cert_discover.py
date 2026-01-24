#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2024, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# A Mechanism for X.509 Certificate Discovery
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfcXXXX.txt
# Based on draft-lamps-okubo-certdiscovery-00
#

from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4055
from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')


# Certificate Discovery Purpose Identifiers

id_pkix = rfc5280.id_pkix

id_ad = id_pkix + (48, )

# "TBD2" in the draft
id_ad_certDiscovery = id_ad + (9992, )

id_on = id_pkix + (8, )

# "TBD3" in the draft
id_on_relatedCertificateDescriptor = id_on + (9993, )

# "TBD4" in the draft
id_rcd = id_pkix + (9994,)

id_rcd_agility      = id_rcd + (1,)
id_rcd_redundency   = id_rcd + (2,)
id_rcd_dual         = id_rcd + (3,)
id_rcd_priv_key_stmt= id_rcd + (4,)
id_rcd_self         = id_rcd + (5,)


# Certificate Discovery Access Method

class DiscoveryPurposeId(univ.ObjectIdentifier):
    pass


class CertHash(univ.Sequence):
    pass


_defaultHashAlgorithm = rfc5280.AlgorithmIdentifier()
_defaultHashAlgorithm['algorithm'] = rfc4055.id_sha256

CertHash.componentType = namedtype.NamedTypes(
    namedtype.NamedType('value', univ.OctetString()),
    namedtype.DefaultedNamedType('hashAlgorithm', _defaultHashAlgorithm)
)


class CertLocation(univ.Sequence):
    pass


CertLocation.componentType = namedtype.NamedTypes(
    namedtype.NamedType('uri', char.IA5String()),
    namedtype.OptionalNamedType('certHash', CertHash().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
)


class CertDiscoveryMethod(univ.Choice):
    pass


CertDiscoveryMethod.componentType = namedtype.NamedTypes(
    namedtype.NamedType('byUri', CertLocation().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    namedtype.NamedType('byInclusion', rfc5280.Certificate()),
    namedtype.NamedType('byLocalPolicy', univ.Null())
)


class RelatedCertificateDescriptor(univ.Sequence):
    pass


RelatedCertificateDescriptor.componentType = namedtype.NamedTypes(
    namedtype.NamedType('method', CertDiscoveryMethod()),
    namedtype.OptionalNamedType('purpose', DiscoveryPurposeId()),
    namedtype.OptionalNamedType('signatureAlgorithm',
        rfc5280.AlgorithmIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.OptionalNamedType('publicKeyAlgorithm',
        rfc5280.AlgorithmIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
)


on_RelatedCertificateDescriptor = rfc5280.AnotherName()
on_RelatedCertificateDescriptor['type-id'] = id_on_relatedCertificateDescriptor
on_RelatedCertificateDescriptor['value'] = RelatedCertificateDescriptor()


# Update the Other Names Map

_otherNamesMapUpdate = {
    id_on_relatedCertificateDescriptor: RelatedCertificateDescriptor(),
}

otherNamesMap.update(_otherNamesMapUpdate)
