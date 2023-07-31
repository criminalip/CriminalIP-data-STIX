import re
from stix2 import (X509Certificate, URL,Relationship)

class CertificateCases:
    def __init__(self) -> None:
        pass
         
    def certificate_case(self,banner,dns_name):
        certificate_object = []
        url_relationships = []
        url_list = []
        
        if ("TLS Certificate" in banner):
            issuer_dn = next((line.split('Issuer Dn: ')[1] for line in banner.split('\n') if line.startswith('Issuer Dn: ')), None)
            subject_dn = next((line.split('Subject Dn: ')[1] for line in banner.split('\n') if line.startswith('Subject Dn: ')), None)
            is_ca = next((line.split('Is Ca: ')[1] for line in banner.split('\n') if line.startswith('\t\tIs Ca: ')), 'None')
            
            certificate = X509Certificate(issuer = issuer_dn,subject = subject_dn,x509_v3_extensions= {"basic_constraints" : "caritical, CA:"+is_ca})
            certificate_object.append(certificate)

            if dns_name:
                url_obj = URL(value=dns_name)
                url_list.append(url_obj)
                url_relationship =Relationship(relationship_type="related-to", source_ref = certificate.id, target_ref=url_obj.id)
                url_relationships.append(url_relationship)

        else:
            pass
        return certificate_object, url_list, url_relationships   