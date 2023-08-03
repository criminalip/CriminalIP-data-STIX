import json
import traceback
from stix2 import Bundle
from Enterprise_config import *

class StixObject:
    def __init__(sel) -> None:
        pass

    def ioc_stix(self,non_empty_values): 
        try:

            bundle = Bundle(objects=non_empty_values)
            bundle_json = bundle.serialize()
            json_obj = json.loads(bundle_json)
            
            StixObject.content()
            
            with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as output_file:
                json.dump(json_obj, output_file, indent=4, ensure_ascii=False)
            
        except Exception as e:
            traceback.print_exc()
            print(e)
            
    def content():
        print("\n=================================================")
        print("Conversion to STIX type has been completed.\nPlease check the \"Criminalip_stix_type.json\" file")
