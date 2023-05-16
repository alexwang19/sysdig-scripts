# Disclaimer

Notwithstanding anything that may be contained to the contrary in your agreement(s) with Sysdig, Sysdig provides no support, no updates, and no warranty or guarantee of any kind with respect to these script(s), including as to their functionality or their ability to work in your environment(s).  Sysdig disclaims all liability and responsibility with respect to any use of these scripts. 

# Delete Acceptance Script

1. Download requirements

```
pip install -r requirements.txt
or
pip3 install -r requirements.txt
```

2. Add acceptance csv files in your preferred directory

3. Format of files should be as follows
```
Vulnerability,ExpirationDate,Reason,Description,ContextType,ContextValue
CVE-1234-1234,2023-03-25,RiskAvoided,my new note,imageName,nginx:1.14
CVE-1235-1235,2023-03-25,RiskTransferred,custom note being added,imageName,myrepo/newimage
```
4. You can run script with command below:

```
python3 main.py --base-url us2.app.sysdig.com --api-token xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --acceptance-files-directory /my/dir/containing/csv/files
```

# Troubleshooting

1. Verify api token is correct
2. Verify sysdig base url is correct
3. Validate that expiration date is not in the past