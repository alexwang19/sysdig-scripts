# Risk Acceptance Script

1. Download requirements

```
pip install -r requirements.txt
or
pip3 install -r requirements.txt
```

2. Add csv files in cve_acceptance_files or your preferred directory. Make sure to update "directory_path" if you using custom path.

3. Format of files should be as follows
```
Vulnerability,ExpirationDate,Reason,Description
CVE-1234-1234,2023-03-25,RiskAvoided,my new note
CVE-1235-1235,2023-03-25,RiskTransferred,custom note being added
CVE-1236-1236,2023-03-25,RiskOwned,test
```

4. Update sysdig api token and base url

5. You can run script with command below:

```
python3 vulnerability_exception.py
```

# Troubleshooting

1. Verify api token is correct
2. Verify sysdig base url is correct
3. Validate that expiration date is not in the past