import json
import traceback
from datetime import datetime
from stix2 import (Bundle)

now = datetime.now()

class StixObject:
    def __init__(sel) -> None:
        pass

    def ioc_stix(self,non_empty_values): 
        try:

            bundle = Bundle(objects=non_empty_values)
            bundle_json = bundle.serialize()
            json_obj = json.loads(bundle_json)
            with open("criminal_data_stix.json", 'w', encoding='utf-8') as output_file:
                json.dump(json_obj, output_file, indent=4, ensure_ascii=False)
            
        except Exception as e:
            traceback.print_exc()
            print(e)