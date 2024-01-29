from stix2 import (AutonomousSystem,Location)
from Enterprise_config import *
from Enterprise_relationship_cases import Relate
from Enterprise_grouping_cases import GroupCases

class Local:
    
    def __init__(self) -> None:
        self.relate = Relate()
        self.group = GroupCases()
        pass

    def create_as_object(self,whois):
        as_info_object =[]
        #Exception as initial value when field value is None
        as_name = whois[0]['as_name'] or "None"
        as_no = whois[0]['as_no'] or 00000
        citys = whois[0]['city'] or "None"
        regions = whois[0]['region'] or "None"
        longitudes = whois[0]['longitude'] or 0.00
        latitudes = whois[0]['latitude'] or 0.00
        countrys = whois[0]['org_country_code'] or "None"

        #Part of the object you create
        as_object = AutonomousSystem(number = as_no, name = as_name)
        as_location = Location(
            name = countrys, 
            description = 'Indicates the location of the band of the owner of this ip.',
            latitude = latitudes, 
            longitude = longitudes, 
            region =  regions, 
            country =countrys, 
            city = citys 
        )
        as_info_object.append(as_object)
        as_info_object.append(as_location)
          
        as_group, as_group_relate = self.group.location_grouping(as_info_object)
         
        as_info_object.extend(as_group)
        as_info_object.extend(as_group_relate)
        return as_info_object 