from stix2 import (Relationship)   
    
class Relate:    
    def __init__(self) -> None:
        pass
        
    def create_relationship_with_objects(self,source,target):
        return Relationship(relationship_type="related-to", source_ref=source[0].id, target_ref=target[0].id)