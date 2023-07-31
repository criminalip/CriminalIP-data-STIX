from datetime import datetime, timedelta
from stix2 import (Grouping,Relationship)


class GroupCases:
    def __init__(self) -> None:
        pass
    
    def ip_category_grouping(self, indicator_case_list):
        ip_category_group_relationship = []
        ip_category_grouping = []
        skip_types = ['grouping', 'tool', 'software', 'relationship', 'course-of-action', 'vulnerability', 'x509-certificate', 'url', 'autonomous-system', "location",'user-account']

        for item in indicator_case_list:
            if item.type == 'indicator':
                if item.indicator_types == ['malicious-activity']:
                    group_name = 'Reputation'
                    group_desc = "A group of things that have done or are doing something malicious."
                    group_context = 'malware-analysis'
                elif item.indicator_types == ['anonymization']:
                    group_name = 'anonymization'
                    group_desc = "This group is suspicious of what actions were performed using proxy, vpn, tor, etc."
                    group_context = 'suspicious-activities'
                else:
                    group_name = 'unknown'
                    group_desc = "These are groups with activities such as Cloud service."
                    group_context = 'unspecified'
            elif item.type == 'malware':
                group_name = 'Reputation'
                group_desc = "A group of things that have done or are doing something malicious."
                group_context = 'malware-analysis'
            elif item.type in skip_types:
                continue

            existing_group = next((group for group in ip_category_grouping if group.name == group_name), None)
            if not existing_group:
                group = Grouping(
                    name=group_name,
                    description=group_desc,
                    context=group_context,
                    object_refs=[item.id]
                )
                ip_category_grouping.append(group)
            else:
                ip_category_grouping.append(existing_group)
                relationship_group = Relationship(relationship_type="related-to", source_ref=existing_group.id, target_ref=item.id)
                ip_category_group_relationship.append(relationship_group)
        
                        
        return ip_category_grouping, ip_category_group_relationship

    
    def location_grouping(self, as_info_object_list):
        as_object_group =[]
        as_object_group_relationship =[]
        for item in as_info_object_list:
            group_name = 'Location'
            group_desc = 'You can find the location of the as_Location and the information of the owner who has this ip.'
            group_context = 'unspecified'           
            existing_group = next((group for group in as_object_group if group.name == group_name), None)
            if not existing_group:
                group = Grouping(
                        name=group_name,
                        description=group_desc,
                        context=group_context,
                        object_refs=[item.id]
                    )
                as_object_group.append(group)
            else:
                as_object_group.append(existing_group)
                relationship_group = Relationship(relationship_type="related-to", source_ref=group.id, target_ref=item.id)
                as_object_group_relationship.append(relationship_group)
        return as_object_group, as_object_group_relationship
    
          
    def open_port_grouping(self, course_of_action_case_list):
        open_port_group_relationship = []
        open_port_group = []
        for item in course_of_action_case_list:
            group_name = 'port'
            group_desc = "The currently open port connected to the ip."
            group_context = 'unspecified'
            existing_group = next((group for group in open_port_group if group.name == group_name), None)
            if not existing_group:
                    group = Grouping(
                        name=group_name,
                        description=group_desc,
                        context=group_context,
                        object_refs=[item.id]
                    )
                    open_port_group.append(group)
            else:
                open_port_group.append(existing_group)
                relationship_group = Relationship(relationship_type="related-to", source_ref=group.id, target_ref=item.id)
                open_port_group_relationship.append(relationship_group)
        return open_port_group, open_port_group_relationship