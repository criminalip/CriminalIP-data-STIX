# **CriminalIP-data-STIX**

- The repository contains Criminal IP Asset Search data in STIX 2.1 JSON format, enabling a quick understanding of threat information for 
specific IPs.


# About 
-   To access IP and domain data, you will need a Criminal IP API key. You can sign up for free at [https://www.criminalip.io/](https://www.criminalip.io/) and obtain your API key from the "My Information" section on the Criminal IP website.

## Criminal IP
Criminal IP is a comprehensive OSINT-based Cyber Threat Intelligence (CTI) providing exclusive threat information on all cyber assets. 
Using AI machine learning technology, it monitors open ports of IP addresses worldwide through a 24/7 scanning process and provides reports with 
a 5-level risk score.
Criminal IP offers tailored plans designed to meet various user needs, providing flexibility and convenience.
You can check function details and credit usage for each plan through the [Pricing page](https://www.criminalip.io/en/pricing). 


## Repository of Criminal IP integrated with STIX
This repository contains the Criminal IP Asset Search data represented in STIX 2.1 JSON collections. Through this repository, you can quickly grasp 
threat information about specific IPs by converting CIP Asset Search-based data into the STIX language.



# Description
This repository consists of two parts:
-  For Enterprise Use (Multiple High-speed APIs provided):
    - You can receive JSON values quickly. 
    - You can identify relationships between multiple IP addresses.
- For Free, Freelancer, and Small Business Use: 
    - You can identify relationships between multiple IP addresses.


# Install 
[You need to install the currently supported library for STIX.](https://pypi.org/project/stix2/) 

Then, you can download the file based on your subscribed Criminal IP plan and install it. 
- CriminalIP_Enterprise_STIX
- CriminalIP_AnotherPlan_STIX

download file command
```shell
git clone https://github.com/criminalip/CriminalIP_Enterprise_STIX.git
git clone https://github.com/criminalip/CriminalIP_AnotherPlan_STIX.git
```

# Usage
Precautions to take before running the tool: 
Check your remaining credit usage, especially for Free, Freelancer, and Small Business use. Sufficient credits are essential for properly visualizing 
malicious activities in the STIX format, which relies on JSON code.

Verify that the IP address you want to investigate is listed in the "ip.txt" file. If it's not present, you can add the desired IP to the "ip.txt" file.



### api_key setting
---
Change the 'cip_KEY' part of config.py to The API_KEY issued from https://www.criminalip.io/mypage/information. 
```python
cip_KEY = '${CRIMINALIP_API_KEY}'
```

### excution python file
---
```shell
python Enterprise_request_data_by_criminalip.py
python AnotherPlan_request_data_by_criminalip.py
```

# Application
### A portion of the JSON in STIX format
---
```json
    {
    "type": "bundle",
    "id": "bundle--5d2e6d75-aa63-42cb-b6e6-71abde602973",
    "objects": [
    {
    "type": "autonomous-system",
    "spec_version": "2.1",
    "id": "autonomous-system--7a61cf13-786c-5d85-9c14-6e5bb73e7e96",
    "number": 44477,
    "name": "Stark Industries Solutions Ltd"
    },
    {
    "type": "location",
    "spec_version": "2.1",
    "id": "location--68e047e8-1429-4cda-9e6c-7f72f4020549",
    "created": "2023-07-18T07:46:30.225447Z",
    "modified": "2023-07-18T07:46:30.225447Z",
    "name": "ch",
    "description": "Indicates the location of the band of the owner of this ip.",
    "latitude": 46.9786,
    "longitude": 7.4483,
    "region": "Bern",
    "country": "ch",
    "city": "Bern"
    },
    {
    "type": "grouping",
    "spec_version": "2.1",
    "id": "grouping--2b39e83d-5610-4c83-acf4-1b29012b2a5c",
    "created": "2023-07-18T07:46:30.225447Z",
    "modified": "2023-07-18T07:46:30.225447Z",
    "name": "Location",
    "description": "You can find the location of the as_Location and the information of the owner who 
    has this ip.",
    "context": "unspecified",
    "object_refs": [
    "autonomous-system--7a61cf13-786c-5d85-9c14-6e5bb73e7e96"
         ]
       },
    etc ...
     ]
    }
```
To visualize the JSON code above in graph format, you can check it at the link below.
- STIX Viewer: https://oasis-open.github.io/cti-stix-visualization/


### Graph of a portion of the output JSON result
![Graph](https://github.com/criminalip/CriminalIP-data-STIX/blob/main/CriminalIP-data-STIX_image/CriminalIP-data-STIX.png)




# Error Code
Below are the descriptions for each error code
--
    - "Your Criminal IP API key is invalid": This error occurs when the API key is entered incorrectly.
    - "An unexpected error occurred": This error occurs when the CIP API server has failed. If you receive this error code, please try again later, or contact us at support@aispera.com.
    - "The target must be an IP address": This error occurs when you enter an incorrect argument value instead of providing an IP address in the target variable.
    - "Unable to call API at the same time": This error occurs when you are not an Enterprise plan user and attempt to make concurrent API calls, which is restricted.
    - "Limit exceeded": This error occurs when you have exhausted all your credits.
