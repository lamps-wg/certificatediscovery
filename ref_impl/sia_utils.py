from pyasn1.type import tag
from pyasn1.codec.der import encoder
from pyasn1_alt_modules import rfc5280
from ref_impl import rfc_cert_discover

def build_related_certificate_descriptor(uri, purpose_id=None):
    """
    Builds a RelatedCertificateDescriptor ASN.1 object.
    
    :param uri: The URI for the certificate location (IA5String).
    :param purpose_id: Optional DiscoveryPurposeId (ObjectIdentifier).
    :return: RelatedCertificateDescriptor instance.
    """
    cert_location = rfc_cert_discover.CertLocation().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    cert_location['uri'] = uri
    
    method = rfc_cert_discover.CertDiscoveryMethod()
    method['byUri'] = cert_location
    
    rcd = rfc_cert_discover.RelatedCertificateDescriptor()
    rcd['method'] = method
    if purpose_id is not None:
        rcd['purpose'] = purpose_id
        
    return rcd

def build_sia_extension_value(purpose_uri_pairs):
    """
    Builds the value of a Subject Information Access extension.
    SIA is a SEQUENCE OF AccessDescription.
    
    Each AccessDescription will have:
    - accessMethod: id-ad-certDiscovery
    - accessLocation: GeneralName of type anotherName (RelatedCertificateDescriptor)
    
    :param purpose_uri_pairs: A list/tuple of (purpose_id, uri) tuples. 
                              purpose_id can be None.
    :return: SubjectInfoAccessSyntax instance.
    """
    sia = rfc5280.SubjectInfoAccessSyntax()
    
    for purpose_id, uri in purpose_uri_pairs:
        rcd = build_related_certificate_descriptor(uri, purpose_id)
        
        another_name = rfc5280.AnotherName().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        another_name['type-id'] = rfc_cert_discover.id_on_relatedCertificateDescriptor
        another_name['value'] = encoder.encode(rcd)
        
        general_name = rfc5280.GeneralName()
        general_name['otherName'] = another_name
        
        access_description = rfc5280.AccessDescription()
        access_description['accessMethod'] = rfc_cert_discover.id_ad_certDiscovery
        access_description['accessLocation'] = general_name
        
        sia.append(access_description)
        
    return sia

def build_sia_extension(purpose_uri_pairs, critical=False):
    """
    Builds an Extension object for Subject Information Access.
    
    :param purpose_uri_pairs: A list/tuple of (purpose_id, uri) tuples.
    :param critical: Boolean indicating if the extension is critical.
    :return: Extension instance.
    """
    sia_value = build_sia_extension_value(purpose_uri_pairs)
    
    extension = rfc5280.Extension()
    extension['extnID'] = rfc5280.id_pe_subjectInfoAccess
    extension['critical'] = critical
    extension['extnValue'] = encoder.encode(sia_value)
    
    return extension
