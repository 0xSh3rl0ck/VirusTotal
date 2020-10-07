import json
import requests


print(r"""

                                    _   _____ ____ ___  _ _  ____ 
                                    / \ /__ __Y  _ \\  \/// \/   _\
                                    | |   / \ | / \| \  / | ||  /  
                                    | |_/\| | | \_/| /  \ | ||  \__
                                    \____/\_/ \____//__/\\\_/\____/
                                                            
""" + r"""
                                   Developed By lToxiC
                                   FB : https://www.facebook.com/0xlToxiC  
                                   Twitter : @SeeifShalabyy                                                          
"""
      )


# ask the user what he/she wants to analyse

answer = input('What do you want to analyse (ip , domain , url , hash) ?\n')

# initalize global apikey

global apikey

apikey = '00c4e361d81446bf1830ece5bf8052df1cca62c718a471ea932a552cb0b310ae'

# validate the user input !

if answer == 'hash':

    hash = input('Enter The Hash ! ')

    params = {"resource": hash, "apikey": apikey}

    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    response = requests.get(url, params=params)
    response_json = json.loads(response.content)

# check if the hash is malicious or not !

    if response_json['positives'] == 0:
        print("The Hash Not Malicious! ")

    elif response_json['positives'] > 0:
        print("The Hash Is Malicious ! ")

    else:
        print("The Hash you are looking for does not exist. Please try again ")

# Check The Domain .

elif answer == 'domain':
    domain = input('Enter The Domain ! ')

    params = {"apikey": apikey, "domain": domain}

    urll = 'https://www.virustotal.com/vtapi/v2/domain/report'

    response = requests.get(urll, params=params)

    response_json = json.loads(response.content)

    result = response_json['detected_referrer_samples']
    list = []
    for line in result:
        list.append(line['positives'])

    final_result = sum(list)

    if final_result == 0:
        print("The Domain Not Malicious! ")

    elif final_result > 0:
        print("The Domain Is Malicious ! ")

    else:
        print("The Domain you are looking for does not exist. Please try again ")

# Check The Url .

elif answer == 'url':
    urll = 'https://www.virustotal.com/vtapi/v2/url/report'

    url = input('Enter The Url ! ')

    params = {'apikey': apikey, 'resource': url}

    response = requests.get(urll, params=params)

    response_json = json.loads(response.content)

    if response_json['positives'] == 0:
        print("The Url Not Malicious! ")

    elif response_json['positives'] > 0:
        print("The Url Is Malicious ! ")

    else:
        print("The Url you are looking for does not exist. Please try again ")

# Check The Ip-Address

elif answer == 'ip':
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

    ip_address = input('Enter The Ip-Address ! ')

    params = {'apikey': apikey, 'ip': ip_address}

    response = requests.get(url, params=params)

    response_json = json.loads(response.content)

    result = response_json['undetected_referrer_samples']
    list = []
    for line in result:
        list.append(line['positives'])

    final_result = sum(list)

    if final_result == 0:
        print("The Ip-Address Not Malicious! ")

    elif final_result > 0:
        print("The Ip-Address Is Malicious ! ")

    else:
        print("The Ip-Address you are looking for does not exist. Please try again")

print("I Hope To See You Again :) ! ")
