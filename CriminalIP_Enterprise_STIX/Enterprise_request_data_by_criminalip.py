import requests
import time
import sys
from Enterprise_config import *
from Enterprise_local_whois import Local
from Enterprise_ip_address_case import IpAddressCases
from Enterprise_process_port import CourseOfActionCases
from Enterprise_indicator_cases import IndicatorCases
from Enterprise_grouping_cases import GroupCases
from Enterprise_change_stix_type import StixObject




def cip_request(endpoint, params, method='GET'):
    headers = {"x-api-key": cip_API}
    url = BASE_URL + endpoint
    
    res = requests.get(url, params=params, headers=headers)
    
    try:
        data = res.json()
        # print(data)
        assert data['status'] == 200

    except AssertionError:
        if data['message'] == 'invalid api key':
            print(f"[-] Invalid URL : {url}, Error message : Your Criminal IP api key is invalid\n")
        elif data['status'] == 500:
            print(f"[-] Invalid URL : {url}, Error message : An unexpected error occured\n")
        elif data['message'] == 'Invalid IP Address.':
            print(f"[-] Invalid URL : {url}, Error message : The target must be an IP address\n")
        elif data['message'] == 'unable to call api at the same time':
            print(f"[-] Invalid URL : {url}, Error message :{data['message']}\n")
        elif data['message'] == "limit exceeded":
            print(f"[-] Invalid URL : {url}, Error message :{data['message']}\n")
        sys.exit(1)

    return data


def process_ip_data(ip_data_result_json,ip):

    
    #Processing required data
    vpn_info = ip_data_result_json['vpn']['data']
    whois = ip_data_result_json['whois']['data']
    port_info = ip_data_result_json['port']['data']
    vulnerability_data = ip_data_result_json['vulnerability']['data']
    ip_category = ip_data_result_json['ip_category']['data']
    
    
    #Create each module instance
    ips = IpAddressCases()
    whose = Local()
    coca = CourseOfActionCases()
    ic = IndicatorCases()
    gc = GroupCases()


    #Create list
    non_empty_values = []
    indicator_list = []

    #Send processed data to the instance you created
    this_ip_owner = whose.create_as_object(whois)

    open_port_course_of_action_case_result = coca.process_port(port_info, vulnerability_data)
    indicator_case1_result = ic.indicator_case1(port_info)
    indicator_case2_result = ic.indicator_case2(ip_category,ip, vpn_info)
    
    
    #To combine separate cases into a single list
    if indicator_case1_result:
        indicator_list.extend(indicator_case1_result)
    if indicator_case2_result:
        indicator_list.extend(indicator_case2_result)
        
    
    
    #Combine content for multiple objects into one content
    
    if this_ip_owner:
        non_empty_values.extend(this_ip_owner)

    if open_port_course_of_action_case_result:
        for item in open_port_course_of_action_case_result:
            non_empty_values.extend(item)
    if indicator_list:
        non_empty_values.extend(indicator_list)
    
    group_objects,group_objects_relate = gc.ip_category_grouping(non_empty_values)
    if group_objects:
        non_empty_values.extend(group_objects)
    if group_objects_relate:
        non_empty_values.extend(group_objects_relate)
        
    #Grouping what should be in the content of the combined non_empty_values
    ip_address = ips.ip_object(ip,non_empty_values)

    #You must put the group back into non_empty_values before sending it to the stix.
    if ip_address:
        non_empty_values.extend(ip_address)
        
    # Forward non_empty_values to the stix function
    return non_empty_values
    
def read_ips_from_file(file_path):
    ips = set()
    with open(file_path, 'r') as f:
        for line in f:
            data = line.strip()
            ips.add(data)
    return ips   

def main():
    stix = StixObject()
    request_values = []
    ips = read_ips_from_file('ip.txt')

    for ip in ips:
        ip_json_result = cip_ip(ip)
        request_values.extend(process_ip_data(ip_json_result, ip))
    stix.ioc_stix(request_values)


def cip_ip(ip):
    params = {"full": True}
    return cip_request(f"v1/ip/data?ip={ip}", params = params)


if __name__ == '__main__':
    main()

    
    
    
    
    
    
    
    
