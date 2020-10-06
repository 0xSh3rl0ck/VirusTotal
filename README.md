# VirusTotal

`VirusTotal` is a Python script that asks the user to enter `url`, `domain`, `ip-address` or `hash` to analyse it and returns to the user the final result if they are `malicious` or `clean`.

# VirusTotal features
  * Scan Urls.
  * Scan Hashes.
  * Scan Ip-Address.
  * Scan Domains.
  * Gives you the final result `malicious or not malicious`.
  
# Prerequisites

You need to get an API key to use the VirusTotal Public API 2.0. To do so, [just sign-up on the service](https://www.virustotal.com/gui/join-us) , go to your profile and click on `API Key`, I've already add my `api key` because it is free but it is better to add `your's` !.

# Installation

First of all make sure to download the latest version of Octopus using the following command :

`git clone https://github.com/seifshalaby/VirusTotal.git`

After that you can start the octopus server by running the following :

`python3 virustotal.py`

You will by greeted with the following once you run it : 
![alt text](https://github.com/seifshalaby/VirusTotal/blob/Python/Capture.PNG)

# How to use

it will ask you what do you want to analyse !
just type either hash , ip-address, domain, url ...
in this example i will test a malicious hash :
![alt text](https://github.com/seifshalaby/VirusTotal/blob/Python/Capture1.PNG)


