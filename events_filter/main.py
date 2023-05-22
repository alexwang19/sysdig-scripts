import requests
import argparse
import time
import json
from datetime import datetime
import pytz

def retrieve_set_sysdig_params():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", dest='sysdig_base_url', type=str,
                        help="Base url of sysdig. ex: us2.app.sysdig.com", required=True)
    parser.add_argument("--api-token", dest='sysdig_api_token',
                        type=str, help="Sysdig API Token", required=True)
    parser.add_argument("--ssl-verification", dest='ssl_verification',
                        type=str, help="enabled or disabled for values. Default is disabled.")
    parser.add_argument("--rule-names", dest='rule_names',
                        type=str, help='list of rule names comma delimited. e.g. "my rule one,my rule two, mynewrule"')
    parser.add_argument("--cluster-name-contains-pattern", dest='cluster_name_contains_pattern',
                        type=str, help="pattern to match on for k8s cluster.")
    parser.add_argument("--cluster-names", dest='cluster_names',
                        type=str, help="List of cluster names to retrieve events for.")
    parser.add_argument("--image-repo-name-contains-pattern", dest='image_repo_name_contains_pattern',
                        type=str, help="pattern to match on for image repo name")
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

    # Calculate the time x minutes ago
    start_time = current_time - (time_duration * 60)

    # Convert the timestamp to an integer
    start_timestamp = str(int(start_time * 1000000000))

    print("Current time: ", end_time)
    print("Start time: ", start_timestamp)
    return end_time, start_timestamp

def convert_to_current_timezone_epoch(cursor_response_data):
    len_index = len(cursor_response_data)
    timestamp_from_data_set = cursor_response_data[len_index-1]['timestamp']
    truncated_timestamp = timestamp_from_data_set[:26] +"Z"
    datetime_obj = datetime.strptime(
        truncated_timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
    local_timezone = pytz.timezone('US/Central')
    datetime_obj_local = datetime_obj.replace(
        tzinfo=pytz.UTC).astimezone(local_timezone)
    epoch_time = int(datetime_obj_local.timestamp())
    return epoch_time


def define_filters(rule_names, cluster_name_contains_pattern, cluster_names, image_repo_name_contains_pattern):
    event_filters = ""
    if rule_names is not None:
        rules_list = rule_names.split(',')
        if len(rules_list) == 1:
            rule_filter = f'ruleName="{rule_names}"'
        else:
            rules = ""
            for rule in rules_list:
                rules += f'"{rule}",'
            rules = rules[:-1]
            rule_filter = f'ruleName in ({rules})'
        event_filters += rule_filter
    if cluster_names is not None:
        cluster_names_list = cluster_names.split(',')
        if len(cluster_names_list) == 1:
            cluster_names_filter = f'kubernetes.cluster.name="{cluster_names}"'
        else:
            clusters = ""
            for cluster in cluster_names_list:
                clusters += f'"{cluster}",'
            clusters = clusters[:-1]
            cluster_names_filter = f'kubernetes.cluster.name in ({clusters})'
        event_filters += cluster_names_filter
    if cluster_name_contains_pattern is not None:
        # cluster_name_contains_patterns_list = cluster_name_contains_patterns.split(',')
        # for cluster_name_contains_pattern in cluster_name_contains_patterns_list:
        cluster_name_contains_pattern_filter = f'kubernetes.cluster.name contains "{cluster_name_contains_pattern}"'
        if event_filters != "":
            event_filters += "and" + cluster_name_contains_pattern_filter
        else:
            event_filters += cluster_name_contains_pattern_filter
    if image_repo_name_contains_pattern is not None:
        # image_repo_name_contains_patterns_list = image_repo_name_contains_patterns.split(',')
        # for image_repo_name_contains_pattern in image_repo_name_contains_patterns_list:
        image_repo_name_contains_pattern_filter = f'container.image.repo contains "{image_repo_name_contains_pattern}"'
        if event_filters != "":
            event_filters += "and" + image_repo_name_contains_pattern_filter
        else:
            event_filters += image_repo_name_contains_pattern_filter
    if event_filters == "":
        raise Exception("!!!No filters provided. Must include one filter!!!")
    return event_filters

def retrieve_events_with_filters(auth_header, url, ssl_verification, end_time, start_time, event_filters):
    events_url_with_filters = url + \
        f'from={start_time}&to={end_time}&filter={event_filters}'
    print("request url: ", events_url_with_filters)
    try:
        print("Retrieving events...")
        print("url with filters : ", events_url_with_filters)
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
    if len(response.json()['data']) == 100 and "prev" in response.json()['page']:
        prev_page = response.json()['page']['prev']
        loop_control = True
        while (loop_control):
            events_url_with_cursor = url + \
                f'cursor={prev_page}&filter={event_filters}&limit=100'
            try:
                cursor_response = requests.get(events_url_with_cursor, headers=auth_header,
                                        verify=ssl_verification)
                cursor_response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                print(" ERROR ".center(80, "-"))
                print("Failed to retrieve cursor events", e)
            except requests.exceptions.RequestException as e:
                print(" ERROR ".center(80, "-"))
                print(e, "Failed retrieving cursor events")
            if "prev" in cursor_response.json()['page']:
                epoch_time_from_existing_data = convert_to_current_timezone_epoch(
                    cursor_response.json()['data'])
                if epoch_time_from_existing_data < int(start_time[:10]):
                    print("Outside time range",
                          epoch_time_from_existing_data, start_time[:10])
                    loop_control = False
                prev_page = cursor_response.json()['page']['prev']
            else:
                loop_control = False
            events_data_json += json.dumps(cursor_response.json()['data'])
    return events_data_json

def write_to_output_file(events_data, output_file):
    with open(output_file, 'w') as f:
        f.write(events_data)
        f.close()

def main():
    args = retrieve_set_sysdig_params()
    auth_header, url = retrieve_sysdig_header_url(args)
    ssl_verification = False
    if (args.ssl_verification == "enabled"):
        ssl_verification = True
    end_time, start_time = retrieve_time_duration(args.time_duration)
    event_filters = define_filters(
        args.rule_names, args.cluster_name_contains_pattern, args.cluster_names, args.image_repo_name_contains_pattern)
    events_data = retrieve_events_with_filters(auth_header, url, ssl_verification, end_time,
                                  start_time, event_filters)
    write_to_output_file(events_data, args.output_file)
    print("Completed!")

if __name__ == "__main__":
    main()


