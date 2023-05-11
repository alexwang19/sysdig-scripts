# Disclaimer

Notwithstanding anything that may be contained to the contrary in your agreement(s) with Sysdig, Sysdig provides no support, no updates, and no warranty or guarantee of any kind with respect to these script(s), including as to their functionality or their ability to work in your environment(s).  Sysdig disclaims all liability and responsibility with respect to any use of these scripts. 

# Events filter Script

1. Download requirements

```
pip install -r requirements.txt
or
pip3 install -r requirements.txt
```
4. You can run script with command below:

```
python3 main.py --base-url us2.app.sysdig.com --api-token xxxxxx-xxxxx-xxxxxx-xxxxx-xxxxxxx --rule-names "DB program spawned process,Container Run as Root User" --cluster-name-contains-pattern test --time-duration 10 --output-file test.json
```

# Troubleshooting

1. Verify api token is correct
2. Verify sysdig base url is correct
3. Verify rule name is correct (no syntax checking)