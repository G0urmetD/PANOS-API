# PANOS-API
Here are a few scripts to interact with the PANOS API.

## pa_firewall.py
```bash
# asking for username and password and generates an api key. The key will be stored encrypted.
python3 pa_firewall.py -generate_api

# checks the status of the firewalls with the system info request [<show><system><info></info></system></show>]
python3 pa_firewall.py -ip 10.1.1.2 -check-status
python3 pa_firewall.py -ip 10.1.1.2 10.1.1.3 10.1.1.4 -check-status
python3 pa_firewall.py -ip-file pa-ips.txt -check-status
```

### generate_api key
The API key is created with the same authorization of a specified user. It is important here that this user has the necessary API authorizations.
The password is used securely with getpass and the file in which the API key is stored is encrypted with Fernet (AES-256 symmetric encryption).

### check-status
Palo Alto has a good documentation regarding API calls (https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/make-your-first-api-call). In that case following API request is used:
```bash
'https://<firewall>//api/?type=op&cmd=<show><system><info></info></system></show>&key=<apikey>'
```

The output will be limited on some of the information aswell, if the firewall has a valid uptime or not.
```xml
<response status="success">
  <result>
    <system>
      <hostname>PA-3050-A</hostname>
      <ip-address>10.2.3.4</ip-address>
      <netmask>255.255.252.0</netmask>
      <default-gateway>10.2.3.1</default-gateway>
      <uptime>0 days, 18:28:38</uptime>
      <serial>001701000529</serial>
      <sw-version>9.0.0-b36</sw-version>
      <av-version>3328-3783</av-version>
      <threat-version>8111-5239</threat-version>
      <wildfire-version>0</wildfire-version>
      <operational-mode>normal</operational-mode>
    </system>
  </result>
</response>
```
