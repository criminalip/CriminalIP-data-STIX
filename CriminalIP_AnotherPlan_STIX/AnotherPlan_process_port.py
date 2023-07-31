from datetime import datetime, timedelta
from stix2 import (CourseOfAction,Relationship)
from AnotherPlan_products_cases import AllProductCases
from AnotherPlan_certificate_cases import CertificateCases
from AnotherPlan_relationship_cases import Relate
from AnotherPlan_maleare_cases import MalwareInfoCase
from AnotherPlan_grouping_cases import GroupCases

today = datetime.today()
thirty_days_ago = today - timedelta(days=30)


class CourseOfActionCases:
    
    def __init__(self) -> None:
        self.products = AllProductCases()
        self.certification = CertificateCases()
        self.malware = MalwareInfoCase()
        self.relationship = Relate()
        self.group_case_ip = GroupCases()
    
    def create_course_of_action_port(self,port_num, product, product_version):
        description = f"There is an open port {port_num} currently using {product}/{product_version} on that IP. If it's a port you're not using, stop it."
        return CourseOfAction(name=port_num, description=description)

    def create_relationship_with_case_and_product(self,course_of_action_port, target_ref):
        return Relationship(relationship_type="related-to", source_ref=course_of_action_port, target_ref=target_ref.id)
    
    def product_object_check(self, vuln_list, port_num, product, product_version, protocol, technologies, banner, tags_string, vuln_exit_check):
        tool_list = []
        software_list = []
        tool_list_vuln = []
        software_list_vuln = []
        tool_list_vuln_relate = []
        software_list_vuln_relate = []
        user_account_list = []
        user_tool_relate_list = []
        
        check_exit_list = []
        
        tool_list_result, tool_list_vuln_result,tool_list_vuln_result_relate,user_account,user_tool_relate = self.products.tool_case(vuln_list, port_num, banner,product, product_version, protocol, technologies, vuln_exit_check)
        if tool_list_result:
            tool_list.extend(tool_list_result)
        if user_account:
            user_account_list.extend(user_account)
        if user_tool_relate:
            user_tool_relate_list.extend(user_tool_relate)

        software_list_result, software_list_vuln_result,soft_list_vuln_result_relate = self.products.software_case(vuln_list, port_num, product, product_version, protocol, banner,tags_string, vuln_exit_check)
        if software_list_result:
            software_list.extend(software_list_result)
        
        
        if (tool_list_vuln_result and software_list_vuln_result) or tool_list_vuln_result:
            if tool_list_vuln_result:
                tool_list_vuln.extend(tool_list_vuln_result)
                tool_list_vuln_relate.extend(tool_list_vuln_result_relate,)
        if software_list_vuln_result and not tool_list_vuln_result:
            if software_list_vuln_result:
                software_list_vuln.extend(software_list_vuln_result)
                software_list_vuln_relate.extend(soft_list_vuln_result_relate)

        check_exit_list.append(tool_list)
        check_exit_list.append(tool_list_vuln)
        check_exit_list.append(tool_list_vuln_relate)
        check_exit_list.append(software_list)
        check_exit_list.append(software_list_vuln)
        check_exit_list.append(software_list_vuln_relate)
        check_exit_list.append(user_account_list)
        check_exit_list.append(user_tool_relate_list)
        
        final_list = self.checking_list_exiting(check_exit_list)
        return final_list, tool_list_result, software_list_result

    #Function to perform if a vulnerability exists.
    def vulnability_exiting(self,port_num, product, product_version, protocol, technologies, banner, sdn_name, tags_string, vulnerability_data,vuln_exit_check):
        vuln_list = [vuln for vuln in vulnerability_data if any(port_item['port'] == port_num for port_item in vuln['open_port_no'])]
        product,tool_list_result,software_list_result = self.product_object_check(vuln_list, port_num, product, product_version, protocol, technologies, banner, tags_string, vuln_exit_check)
        other_product = self.check_other_object(banner,sdn_name,tags_string,software_list_result)
    
        return product, other_product,tool_list_result,software_list_result
    
    #Function to perform when no vulnerability exists.       
    def not_vulnability_exiting(self,port_num, product, product_version, protocol, technologies, banner, sdn_name, tags_string,vuln_exit_check):
        vuln_list = []
        
        # Go to a function that checks for the presence of tools, software, user-account, etc
        product,tool_list_result, software_list_result = self.product_object_check(vuln_list, port_num, product, product_version, protocol, technologies, banner, tags_string, vuln_exit_check)
        # Go to other certificates, url, and malicious tags to a function that checks the existence of them
        other_product = self.check_other_object(banner,sdn_name,tags_string,software_list_result)
        
        return product, other_product,tool_list_result,software_list_result
    
    # A function that checks certificate, url, and malicious tag information and creates relationship objects between those objects.      
    def check_other_object(self,banner,sdn_name,tags_string,software_list_result):
        certificate_list = []
        certifi_relate_list = []
        url_object_list = []
        url_object_relate_list = []
        malicious_list = []
        check_exit_list = []
        
        
        #A function that goes to the object module function for the certificate and includes creating an url object and creating a relationship if the sdn name exists in the certificate.
        certificate, url_list, url_relationships = self.certification.certificate_case(banner,sdn_name)
        #Put the returned result value into each list.
        certificate_list.extend(certificate)
        url_object_list.extend(url_list)
        url_object_relate_list.extend(url_relationships)
        
        #Object creation function performed if the malicious tag exists in the banner.
        malwares,mal_url,mal_url_relate = self.malware.malware_case1(banner,tags_string)
        malicious_list.extend(malwares)
        malicious_list.extend(mal_url)
        malicious_list.extend(mal_url_relate)

        
        #certificate The process of creating a relationship with the software when the object is created.
        if certificate and software_list_result:
            relate_with_certifi_soft = self.relationship.create_relationship_with_objects(software_list_result,certificate)
            certifi_relate_list.append(relate_with_certifi_soft)
        
        #To determine if each list exists, perform a single list.         
        check_exit_list.append(certificate_list)
        check_exit_list.append(certifi_relate_list)
        check_exit_list.append(url_object_list)
        check_exit_list.append(url_object_relate_list)
        check_exit_list.append(malicious_list)

        #Finally, the contents in the final_list contain only non-empty non-empty lists in the check_exit_list.
        final_list = self.checking_list_exiting(check_exit_list)
        return final_list
          

    
    # A function that checks the existence of a list for each object and returns it as one list.    
    def checking_list_exiting(self,exiting_check_list):
        listing = []
        
        for item_list in exiting_check_list:
            if len(item_list) > 0:
                listing.extend(item_list)            
        return listing    
    
    def process_port(self, port_info, vulnerability_data):
        course_of_action_case_object = []
        relationship_with_case_and_product = []
        when_vuln_exit_object = []
        when_vuln_not_exit_object = []
        non_empty_values = []
        processed_ports = set()
        
        for port in port_info:
            port_num = port['open_port_no']
            product = port['app_name']
            product_version = port['app_version']
            protocol = port['protocol']
            banner = port['banner']
            sdn_name = port['sdn_common_name']
            tags_string = port['tags']
            technologies = port['technologies']
            vuln_exit_check = port['is_vulnerability']
            time_str = port['confirmed_time']
            confirmed_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            
            if port_num in processed_ports or confirmed_time < thirty_days_ago:
                continue
            processed_ports.add(port_num)

            naming = f"port:{port_num} Vulnerability sexiste in {product}/{product_version}"
            existing_port = next((port for port in course_of_action_case_object if port.name == naming),None)
            
            #Logic to be performed when the port is the first content to be generated
            if not existing_port:
                #Creating a course of action object
                course_of_action_case_port = self.create_course_of_action_port(port_num,product,product_version)
                course_of_action_case_object.append(course_of_action_case_port)
                
                #Determine if a vulnerability exists or does not exist for that port
                if vuln_exit_check is True:
                    #If a vulnerability exists, go to vulnerability_exiting()
                    product, other_product,tool_list_result,software_list_result = self.vulnability_exiting(port_num,
                                          product, product_version, protocol,technologies,
                                          banner, sdn_name, tags_string, 
                                          vulnerability_data, vuln_exit_check)
                    #Save the result value returned by vulnerability_exiting() to the list 
                    if product:
                        when_vuln_exit_object.append(product)
                    if other_product:
                        when_vuln_exit_object.append(other_product)

                if (vuln_exit_check is None) or (vuln_exit_check is False) :
                    #If the vulnerability does not exist, go to not_vulability_exiting() 
                    product, other_product,tool_list_result,software_list_result = self.not_vulnability_exiting(port_num, 
                                                  product, product_version, protocol, technologies, 
                                                  banner, sdn_name, tags_string, 
                                                  vuln_exit_check)
                    # Save the result value returned by not_vulability_exiting() to the list
                    if product:
                        when_vuln_not_exit_object.append(product)
                    if other_product:
                        when_vuln_not_exit_object.append(other_product)
                
                # tool_list_result,software returned by the vulnerability_exiting/not_vulability_exiting function has a value stored in the_list_result variable and creates a relationship with the port
                if (tool_list_result and software_list_result) or tool_list_result:
                        for t in tool_list_result:
                            relationship = self.create_relationship_with_case_and_product(course_of_action_case_port, t)
                            relationship_with_case_and_product.append(relationship)

                if software_list_result:
                        for s in software_list_result:
                            relationship = self.create_relationship_with_case_and_product(course_of_action_case_port, s)
                            relationship_with_case_and_product.append(relationship)
                            
        # Create a group object by accessing open_port_grouping() that exists in the grouping module to perform the grouping of course of action objects for that port into one group                   
        course_of_action_group, course_of_action_relationship = self.group_case_ip.open_port_grouping(course_of_action_case_object) 

        
        # Finally, it checks the existence of a list of results generated by each object and, if so, puts it in the value of non_empty_values and sends it at once.
        if course_of_action_group:
            non_empty_values.append(course_of_action_group)
        if course_of_action_relationship:
            non_empty_values.append(course_of_action_relationship)
        if course_of_action_case_object:
            non_empty_values.append(course_of_action_case_object)
        if relationship_with_case_and_product:
                non_empty_values.append(relationship_with_case_and_product)
        for item in when_vuln_exit_object:
            if item:
                non_empty_values.append(item)
        for item in when_vuln_not_exit_object:
            if item:
                non_empty_values.append(item)
                
        return non_empty_values
    
    
    