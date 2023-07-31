import json
from stix2 import Bundle

class StixObject:
    def __init__(self):
        pass

    def ioc_stix(self, non_empty_values):
        bundle_objects = non_empty_values
        bundle = Bundle(objects=bundle_objects)
        bundle_json = bundle.serialize()
        json_obj = json.loads(bundle_json)

        with open("Criminalip_stix_type.json", 'w', encoding='utf-8') as output_file:
            json.dump(json_obj, output_file, indent=4, ensure_ascii=False)
