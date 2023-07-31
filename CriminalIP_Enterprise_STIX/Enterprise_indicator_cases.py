from datetime import datetime, timedelta
from stix2 import (Indicator)
from Enterprise_grouping_cases import GroupCases

today = datetime.today()
thirty_days_ago = today - timedelta(days=30)

class IndicatorCases:
    def __init__(self):
        self.group_case_ip = GroupCases()

    
    def indicator_case1(self, port_info):
        indicator_case1_list = []
        processed_ports = set()
        
        for port in port_info:
            port_num = port['open_port_no']
            banner = port['banner']
            time_str = port['confirmed_time']
            confirmed_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")

            if port_num in processed_ports or confirmed_time < thirty_days_ago:
                continue
            processed_ports.add(port_num)

            if port_num == 80 or port_num == 443 or 'HTTP' in banner or 'HTTPS' in banner:
                fingerprint_sha256 = None
                fingerprint_md5 = None
                
                for line in banner.split('\n'):
                    if line.startswith('\tFingerprint Sha256: '):
                        fingerprint_sha256 = line.split('Fingerprint Sha256: ')[1]
                    elif line.startswith('Fingerprint Md5: '):
                        fingerprint_md5 = line.split('Fingerprint Md5: ')[1]

                    if fingerprint_sha256 and fingerprint_md5:
                        break
                    
                if fingerprint_sha256 and fingerprint_md5:
                    pattern = f"[web:hashes.'SHA-256'='{fingerprint_sha256}' OR web:hashes.'MD5'='{fingerprint_md5}']"
                    indicator = Indicator(
                        indicator_types=['unknown'],
                        name='unknowns',
                        description='The hash value of the content related to the certificate of the web page is written. Determine if the corresponding hash value is malicious or not.',
                        pattern=pattern,
                        pattern_type="stix",
                    )
                    indicator_case1_list.append(indicator)
                else:
                    continue

        return indicator_case1_list
    
    def indicator_case2(self, ip_category, ip, vpn_info):
        indicator_case2_list = []
        
        for category in ip_category:
            indicator_type = category['type']
            indicator_name = category['detect_source']
            # indicator_hash = category['Md5']
            time_str = category['confirmed_time']
            confirmed_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            
            if confirmed_time < thirty_days_ago:
                continue
            if indicator_type in ['proxy', 'vpn', 'tor']:
                pattern = f"[ip:value = '{ip}']"
                indicator = Indicator(
                    indicator_types=['anonymization'], 
                    name=indicator_name, 
                    description='The hash value of the content related to the certificate of the web page is written. Determine if the corresponding hash value is malicious or not.', 
                    pattern=pattern, 
                    pattern_type="stix"
                    )
            elif indicator_type == 'MISP': 
                pattern = f"[ip:value = '{ip}']"
                # pattern = f"[file:name.'MD5' = '{indicator_hash}]"  
                indicator = Indicator(
                    indicator_types=['malicious-activity'], 
                    name=indicator_name, 
                    description='The hash value of the content related to the certificate of the web page is written. Determine if the corresponding hash value is malicious or not.', 
                    pattern=pattern, 
                    pattern_type="stix"
                    )
            else:
                pattern = f"[ip:value = '{ip}']"
                indicator = Indicator(
                    indicator_types=['unknown'], 
                    name=indicator_name, 
                    description='The hash value of the content related to the certificate of the web page is written. Determine if the corresponding hash value is malicious or not.', 
                    pattern=pattern, 
                    pattern_type="stix"
                    )            
            indicator_case2_list.append(indicator)
            
        if vpn_info:
            for vpn in vpn_info:
                indicator_name = vpn['vpn_name']
                indicator_pattern_url = vpn['vpn_source_url']
                indicator_url = vpn['vpn_url']
                times_str = vpn['confirmed_time']
                confirmed_time = datetime.strptime(times_str, "%Y-%m-%d %H:%M:%S")
                
                if confirmed_time < thirty_days_ago:
                    continue
                
                pattern = f"[url:value = '{indicator_pattern_url}']"
                indicator = Indicator(
                    indicator_types=['anonymization'], 
                    name=indicator_name, 
                    description=f'History exists with vpn in {indicator_url}. If you are not using vpnip, it seems that blocking is necessary.', 
                    pattern=pattern, 
                    pattern_type="stix"
                    )
                indicator_case2_list.append(indicator)

        return indicator_case2_list
