# Disclaimer

Notwithstanding anything that may be contained to the contrary in your agreement(s) with Sysdig, Sysdig provides no support, no updates, and no warranty or guarantee of any kind with respect to these script(s), including as to their functionality or their ability to work in your environment(s).  Sysdig disclaims all liability and responsibility with respect to any use of these scripts. 

# Events filter Script

1. Download requirements

```
pip install -r requirements.txt
or
pip3 install -r requirements.txt
```
2. You can run script with command below:

```
python3 main.py --base-url us2.app.sysdig.com --api-token xxxxxx-xxxxx-xxxxxx-xxxxx-xxxxxxx --rule-names "DB program spawned process,Container Run as Root User" --cluster-name-contains-patterns test,eks,new --image-repo-name-contains-patterns docker.io/library/tomcat,test --time-duration 10 --output-file test.json
```

# JQ to parse data

```
cat test.json| jq '.[] | select(.actions | .[]?.type=="container killed") | "Timestamp: " + .timestamp + " K8S ClusterName: " + .labels."kubernetes.cluster.name" + " K8s Namespace: " + .labels."kubernetes.namespace.name" + " ImageRepo: " + .content.fields."container.image.repository" + " PolicyName: " + .name + " " + "RuleName: " + .content.ruleName + " ACTION: " + (.actions | .[].type)'
```

# Troubleshooting

1. Verify api token is correct
2. Verify sysdig base url is correct
3. Verify filters are correct (no syntax checking)