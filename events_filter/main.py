import requests
import argparse
import time
import json

def retrieve_set_sysdig_params():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", dest='sysdig_base_url', type=str,
                        help="Base url of sysdig. ex: us2.app.sysdig.com", required=True)
    parser.add_argument("--api-token", dest='sysdig_api_token',
                        type=str, help="Sysdig API Token", required=True)
    parser.add_argument("--ssl-verification", dest='ssl_verification',
                        type=str, help="enabled or disabled for values. Default is disabled.")
    parser.add_argument("--rule-names", dest='rule_names',
                        type=str, help='list of rule names comma delimited. e.g. "my rule one,my rule two, mynewrule"', required=True)
    parser.add_argument("--cluster-name-contains-pattern", dest='cluster_name_contains_pattern',
                        type=str, help="pattern to match on for k8s cluster. e.g. mycluster123", required=True)
    parser.add_argument("--time-duration", dest='time_duration',
                        type=int, help="enter int value for time duration to use for events. e.g 10 for 10minutes", required=True)
    parser.add_argument("--output-file", dest='output_file',
                        type=str, help="enter output file", required=True)
    return parser.parse_args()


def retrieve_sysdig_header_url(args):
    auth_token = args.sysdig_api_token
    auth_header = {'Authorization': 'Bearer ' + auth_token}
    base_url = args.sysdig_base_url.replace("https://", "")
    url = f'https://{base_url}/api/v1/secureEvents?'
    return auth_header, url

def retrieve_time_duration(time_duration):
    # Get the current time in seconds since the epoch
    current_time = time.time()

    end_time = str(int(time.time() * 1000000000))

    # Calculate the time 10 minutes ago
    start_time = current_time - (time_duration * 60)

    # Convert the timestamp to an integer
    start_timestamp = str(int(start_time * 1000000000))

    print("Current time: ", end_time)
    print("Start time: ", start_timestamp)
    return end_time, start_timestamp


def retrieve_events(auth_header, url, ssl_verification, end_time, start_time, rule_names, cluster_name_contains_pattern):
    rules_list = rule_names.split(',')
    if len(rules_list) == 1:
        rule_filter = f'ruleName="{rule_names}"'
    else:
        rules = ""
        for rule in rules_list:
            rules += f'"{rule}",'
        rules = rules[:-1]
        rule_filter = f'ruleName in ({rules})'
    cluster_name_contains_pattern_filter = f'kubernetes.cluster.name contains "{cluster_name_contains_pattern}"'
    events_url_with_filters = url + \
        f'from={start_time}&to={end_time}&filter={rule_filter}and{cluster_name_contains_pattern_filter}'
    print("request url: ", events_url_with_filters)
    try:
        print("Retrieving events...")
        response = requests.get(events_url_with_filters, headers=auth_header,
                                verify=ssl_verification)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(" ERROR ".center(80, "-"))
        print("Failed to retrieve events", e)
    except requests.exceptions.RequestException as e:
        print(" ERROR ".center(80, "-"))
        print(e, "Failed retrieving events")
    events_data_json = json.dumps(response.json()['data'])

    return events_data_json

def write_to_output_file(events_data, output_file):
    with open(output_file, 'w') as f:
        # Write data to the file
        f.write(events_data)
        f.close()


def main():
    args = retrieve_set_sysdig_params()
    auth_header, url = retrieve_sysdig_header_url(args)
    ssl_verification = False
    if (args.ssl_verification == "enabled"):
        ssl_verification = True
    end_time, start_time = retrieve_time_duration(args.time_duration)
    events_data = retrieve_events(auth_header, url, ssl_verification, end_time,
                    start_time, args.rule_names, args.cluster_name_contains_pattern)
    write_to_output_file(events_data, args.output_file)


if __name__ == "__main__":
    main()

# python3 vulnerability_exception.py --base-url us2.app.sysdig.com --api-token c1190019-2540-42f6-8647-d3a0131bed5e --rule_names "DB program spawned process" --cluster-name-contains-pattern test --time-duration 1440

# # Get the current time in seconds since the epoch
# current_time = time.time()

# start_time = str(int(time.time() * 1000000000))

# # Calculate the time 10 minutes ago
# ten_minutes_ago = current_time - (10 * 60)

# # Convert the timestamp to an integer
# ten_minutes_ago_timestamp = str(int(ten_minutes_ago * 1000000000))

# print("Current time: ", start_time)
# print("Time 10 minutes ago: ", ten_minutes_ago_timestamp)

# # SYSDIG API TOKEN
# auth_token = 'c1190019-2540-42f6-8647-d3a0131bed5e'
# auth_header = {'Authorization': 'Bearer ' + auth_token}
# vulnerability_exception_default_list = "global"
# # SYSDIG URL - INSERT APPROPRIATE SYSDIG URL POINTING TO CORRECT REGION
# url = f'https://us2.app.sysdig.com/api/v1/secureEvents?from={ten_minutes_ago_timestamp}&to={start_time}&filter=ruleName="Container Run as Root User"andcontainer.image.repo contains "ng"'

# # SSL VERIFICATION
# ssl_verification_flag=False

# response = requests.get(url, headers=auth_header, verify=ssl_verification_flag)

# print(response.json())

# 1683757393000000000
# 1683756566728160000


