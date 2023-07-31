import requests
import time
import sys
from AnotherPlan_config import *
from AnotherPlan_local_whois import Local
from AnotherPlan_ip_address_case import IpAddressCases
from AnotherPlan_process_port import CourseOfActionCases
from AnotherPlan_indicator_cases import IndicatorCases
from AnotherPlan_change_stix_type import StixObject
from AnotherPlan_grouping_cases import GroupCases



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
            print(f"[-] Invalid URL : {url}, status message : Your CriminalIP API key is invalid\n")
        elif data['status'] == 500:
            print(f"[-] Invalid URL : {url}, status message : An unexpected error occured\n")
        elif data['message'] == 'Invalid IP Address.':
            print(f"[-] Invalid URL : {url}, status message : The target must be an IP address\n")
        elif data['message'] == 'unable to call api at the same time':
            print(f"[-] Invalid URL : {url}, status message :{data['message']}\n")
        elif data['message'] == "limit exceeded":
            print(f"[-] Invalid URL : {url}, status message :{data['message']}\n")
        sys.exit(1)

    return data


def process_ip_data(ip_data_result_json,ip):

    
    #필요한 데이터 가공
    vpn_info = ip_data_result_json['vpn']['data']
    whois = ip_data_result_json['whois']['data']
    port_info = ip_data_result_json['port']['data']
    vulnerability_data = ip_data_result_json['vulnerability']['data']
    ip_category = ip_data_result_json['ip_category']['data']
    
    
    #각각의 모듈 인스턴스 생성
    ips = IpAddressCases()
    whose = Local()
    coca = CourseOfActionCases()
    ic = IndicatorCases()
    gc = GroupCases()


    #list 생성
    non_empty_values = []
    indicator_list = []

    #생성한 인스턴스에 가공한 데이터 보내기
    this_ip_owner = whose.as_object_case1(whois)

    open_port_course_of_action_case_result = coca.process_port(port_info, vulnerability_data)
    indicator_case1_result = ic.indicator_case1(port_info)
    indicator_case2_result = ic.indicator_case2(ip_category,ip, vpn_info)
    
    
    #분리되어 있는 case 하나의 리스트로 합치기
    if indicator_case1_result:
        indicator_list.extend(indicator_case1_result)
    if indicator_case2_result:
        indicator_list.extend(indicator_case2_result)
        
    
    
    #여러 object에 대한 내용을 하나의 내용으로 합치기
    
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
        
    #합쳐진 non_empty_values에 대한 내용에서 grouping해야 하는 내용 grouping하기
    ip_address = ips.ip_object(ip,non_empty_values)

    #stix에 보내기전에 다시 그룹을 non_empty_values에 넣어야 함.
    if ip_address:
        non_empty_values.extend(ip_address)
        
    # non_empty_values를 stix 함수에 전달
    
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
    start_time = time.time()
    print("시작 시간:", start_time)
    main()
    end_time = time.time()
    print("끝나는 시간:", end_time)
    
    execution_time = end_time - start_time
    print("실행 시간:", execution_time)
    
    
    
    
    
    
    
    
