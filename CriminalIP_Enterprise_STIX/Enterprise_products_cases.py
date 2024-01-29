import re
from datetime import datetime, timedelta
from stix2 import (AutonomousSystem,Tool,Software,UserAccount,Relationship)
from Enterprise_vulnerability_cases import Vulns
from Enterprise_config import IS_TAGS
today = datetime.today()
thirty_days_ago = today - timedelta(days=30)

class AllProductCases:
    def __init__(self) -> None:
        self.vuln = Vulns()

    def user_account_case(self,netbios_domain_name,tool):
        user_account_objet =[]  
        user_account_objet_software_relate = []

        user_account = UserAccount(user_id = netbios_domain_name)
        user_account_objet.append(user_account)
        relate_user_software = Relationship(
            relationship_type="Attributed-to", 
            source_ref=tool[0].id, 
            target_ref=user_account_objet[0].id)
        
        user_account_objet_software_relate.append(relate_user_software)
        
        return user_account_objet, user_account_objet_software_relate


    '''
    software object
    It is used as an object to show the contents that appear on the network, and it seems right to write the contents of product and version in criminalip.
    '''    
    def software_case(self,vuln_list,port_num,product,product_version, protocol, banner,tags_string,vuln_exit_check):
        software_object =[]
        soft_vuln_object =[]
        soft_vuln_relate_object =[]

        pattern = re.compile('<title>(.*?)</title>')
        pattern2 = r'<meta name="description" content="(.*?)" />'
        match = re.search(pattern2, banner)
        parsed_string = re.search(pattern,banner)
        
        if parsed_string :
            extracted_string = parsed_string.group(1)
        elif "MikroTik bandwidth-test server" in banner:
            extracted_string = "MikroTik bandwidth-test server"
        elif match:
            extracted_string = match.group(1)
        elif protocol and ( product == "Unknown" or product == ""):
            extracted_string = protocol
        elif "Server: " in  banner:
            extracted_string = str(banner.split('Server: ')[1].split('\n', 1)[0])
        else:
            extracted_string = ""
            
        if not any(tag in IS_TAGS for tag in tags_string):
            tags_string = ', '.join(tags_string)
        else:
            tags_string = None
            

        if extracted_string:
            software = Software(name = extracted_string, version = product_version, vendor = product)
            software_object.append(software)
            
        if tags_string:
            software = Software(name=tags_string, version=product_version, vendor=product)
            software_object.append(software)
            
        elif extracted_string == 'None' or extracted_string == '' :
            software = Software(name = product, version = product_version, vendor = product)
            software_object.append(software)
        
        
        if vuln_exit_check and software_object:
            soft_vuln, soft_vuln_relate = self.vuln.process_vulnerabilities(vuln_list, port_num, product, product_version, software_object)
            soft_vuln_object.extend(soft_vuln)
            soft_vuln_relate_object.extend(soft_vuln_relate)

        return software_object, soft_vuln_object, soft_vuln_relate_object    

    '''
    AS Object 객체 
    as의 속성을 표기하는 객체입니다.
    '''              
    def tool_case(self, vuln_list, port_num, banner, product, product_version, protocol, technologies, vuln_exit_check):
        tool_object = []
        tool_vuln_object = []
        tool_vuln_relate_object =[]
        user_account_list = []
        user_tool_relate_list = []
        

        
        if protocol in ['RDP', 'SSH', 'VNC', 'Telnet']:
            if "Target_Name:" in banner and protocol == 'RDP':
                os_name = str(banner.split('OS: ')[1].split('\n', 1)[0])
                os_build = str(banner.split('OS_Build: ')[1].split('\n', 1)[0])
                tool = Tool(
                    name=f"{os_name} / {os_build}({protocol})",
                    description=f"{product}/{product_version}",
                    tool_types=['remote-access'],
                    tool_version=product_version
                ) 
                tool_object.append(tool)

                netbios_domain_name = str(banner.split('NetBIOS_Domain_Name: ')[1].split('\n', 1)[0])
                # netbios_computer_name = str(banner.split('NetBIOS_Computer_Name: ')[1].split('\n', 1)[0])
                user_accout_object, user_tool_relate= self.user_account_case(
                    netbios_domain_name,tool_object
                    )
                user_account_list.extend(user_accout_object)
                user_tool_relate_list.extend(user_tool_relate)
            else:
                tool = Tool(
                    name=f"{product}/{product_version} ({protocol})",
                    description=f"{product}/{product_version}",
                    tool_types=['remote-access'],
                    tool_version=product_version
                ) 
            tool_object.append(tool)
            
        elif len(technologies) != 0:
            tool = Tool(
                name=product,
                description=f"{product}/{product_version}",
                tool_types=technologies,
                tool_version=product_version
            )
            tool_object.append(tool)
            
        if vuln_exit_check and tool_object:
            tool_vuln,tool_vuln_relate = self.vuln.process_vulnerabilities(
                vuln_list, port_num, product, product_version, tool_object
                )
            tool_vuln_object.extend(tool_vuln)
            tool_vuln_relate_object.extend(tool_vuln_relate)

        return tool_object, tool_vuln_object, tool_vuln_relate_object,user_account_list,user_tool_relate_list


    def as_object_case1(self,whois):
        as_info_object =[]
        
        for who in whois:
            as_name = who['as_name']
            as_no = who['as_no']
            as_object = AutonomousSystem(number = as_no, name = as_name)
            as_info_object.append(as_object)
            
        return as_info_object 
        
    