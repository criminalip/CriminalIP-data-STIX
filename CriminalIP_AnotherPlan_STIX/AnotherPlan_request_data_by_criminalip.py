import requests
import time
import sys
import os
import ipaddress
from AnotherPlan_config import cip_API,BASE_URL,INPUT_FILE_PATH
from AnotherPlan_local_whois import Local
from AnotherPlan_ip_address_case import IpAddressCases
from AnotherPlan_process_port import CourseOfActionCases
from AnotherPlan_indicator_cases import IndicatorCases
from AnotherPlan_change_stix_type import StixObject
from AnotherPlan_grouping_cases import GroupCases



def cip_request(endpoint, method='GET'):
    headers = {"x-api-key": cip_API}
    url = BASE_URL + endpoint
    
    res = requests.get(url, headers=headers)
    
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
    this_ip_owner = whose.as_object_case1(whois)

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

   
def check_private_ip(ip):
    if ipaddress.IPv4Address(ip).is_global:
        # print(ipaddress.IPv4Address(ip).is_global)
        return True
    return False

def read_ips_from_file(INPUT_FILE_PATH):
    ips = set()
    if not os.path.exists(INPUT_FILE_PATH) or os.path.getsize(INPUT_FILE_PATH) == 0:
        print("[-] The 'ip.txt' file is empty or does not exist. Please enter the IP addresses you want to convert!")
        sys.exit(1)
        
    with open(INPUT_FILE_PATH, 'r') as f:
        for line in f:
            data = line.strip()
            if check_private_ip(data):
                ips.add(data)
    return ips   

def main():
    stix = StixObject()
    request_values = []
    ips = read_ips_from_file(INPUT_FILE_PATH)
    content(ips)
    for ip in ips:
        # time.sleep(2)
        ip_json_result = cip_ip(ip)
        request_values.extend(process_ip_data(ip_json_result, ip))
    stix.ioc_stix(request_values)

def content(ips):
    print(f">>The ip to convert is {ips}")    
    print(">> Started converting Criminal ip's data to STIX format.")
    print(">> please wait for a moment!!")

def cip_ip(ip):
    return cip_request(f"v1/asset/ip/report?ip={ip}&full=true")


if __name__ == '__main__':
    main()

    
    
    
    
    
    
    
    
