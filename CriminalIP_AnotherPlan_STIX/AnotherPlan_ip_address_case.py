from stix2 import (IPv4Address,Relationship)


class IpAddressCases:
    def __init__(self) -> None:
        pass
    
    def ip_object(self,ip,non_empty_values):
        ip_with_other_object_relate = []
        create_relationship = set()
        ipv4_address = IPv4Address(value = ip)    
        # print(non_empty_values)
        for inner in non_empty_values:
            # print(inner)
            if (inner.type == 'grouping') and (inner.id not in create_relationship) :
                relationship_group = Relationship(relationship_type='related-to', source_ref=ipv4_address.id, target_ref=inner.id)
                ip_with_other_object_relate.append(relationship_group)
                create_relationship.add(inner.id)
        ip_with_other_object_relate.append(ipv4_address)
        return ip_with_other_object_relate