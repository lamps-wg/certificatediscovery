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

from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')


# Certificate Discovery Access Method

id_pkix = rfc5280.id_pkix

id_ad = id_pkix + (48, )

id_ad_certDiscovery = id_ad + (9991, )

id_on = id_pkix + (8, )

id_on_relatedCertificateDescriptor = id_on + (9992, )


class RelatedCertificateDescriptor(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('relatedCertificateLocation',
            rfc5280.GeneralName()),
        namedtype.OptionalNamedType('relatedCertificateSignatureAlgorithm',
            rfc5280.AlgorithmIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('relatedCertificatePublicKeyAlgorithm',
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
