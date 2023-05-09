# Disclaimer

Notwithstanding anything that may be contained to the contrary in your agreement(s) with Sysdig, Sysdig provides no support, no updates, and no warranty or guarantee of any kind with respect to these script(s), including as to their functionality or their ability to work in your environment(s).  Sysdig disclaims all liability and responsibility with respect to any use of these scripts. 

# Risk Acceptance Script

1. Download requirements

```
pip install -r requirements.txt
or
pip3 install -r requirements.txt
```

2. Add acceptance csv files in your preferred directory

3. Format of files should be as follows
```
Vulnerability,ExpirationDate,Reason,Description
CVE-1234-1234,2023-03-25,RiskAvoided,my new note
CVE-1235-1235,2023-03-25,RiskTransferred,custom note being added
CVE-1236-1236,2023-03-25,RiskOwned,test
```
4. You can run script with command below:

```
python3 vulnerability_exception.py --base-url us2.app.sysdig.com --api-token xxxxxx-xxxxx-xxxxxx-xxxxx-xxxxxxx --acceptance-files-directory /my/test/path/ --ssl-verification enabled
```

# Troubleshooting

1. Verify api token is correct
2. Verify sysdig base url is correct
3. Validate that expiration date is not in the past