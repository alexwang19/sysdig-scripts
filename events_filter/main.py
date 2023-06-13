import requests
import argparse
import time
import json
from datetime import datetime
import pytz
import re
import csv


def set_proxy_config(proxies):
    http_proxy = proxies
    https_proxy = proxies
    proxies = {
        "http": http_proxy,
        "https": https_proxy,
    }
    return proxies

def retrieve_set_sysdig_params():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", dest='sysdig_base_url', type=str,
                        help="Base url of sysdig. ex: us2.app.sysdig.com", required=True)
    parser.add_argument("--api-token", dest='sysdig_api_token',
                        type=str, help="Sysdig API Token", required=True)
    parser.add_argument("--ssl-verification", dest='ssl_verification',
                        type=str, help="enabled or disabled for values. Default is disabled.")
    parser.add_argument("--proxies", dest='proxies',
                        type=str, help="list of proxies")
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


def check_word_in_string(string):
    pattern = r'\bin\b'
    if re.search(pattern, string):
        return True
    else:
        return False

def separate_rules_containing_in(rules):
    rule_names_containing_in = []
    rule_names_not_containing_in = []
    if (rules is not None):
        rule_names = rules.split(',')
        for rule in rule_names:
            if check_word_in_string(rule):
                rule_names_containing_in.append(rule)
            else:
                rule_names_not_containing_in.append(rule)
    return rule_names_containing_in, rule_names_not_containing_in

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
    print("this is timestamp from data set, ", timestamp_from_data_set)
    print("lenght of timestamp from data set, ", len(timestamp_from_data_set))
    if len(timestamp_from_data_set) >= 26:
        truncated_timestamp = timestamp_from_data_set[:26] +"Z"
    else:
        truncated_timestamp = timestamp_from_data_set
    print("this is truncated timestamp, ", truncated_timestamp)
    datetime_obj = datetime.strptime(
        truncated_timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
    local_timezone = pytz.timezone('US/Central')
    datetime_obj_local = datetime_obj.replace(
        tzinfo=pytz.UTC).astimezone(local_timezone)
    epoch_time = int(datetime_obj_local.timestamp())
    return epoch_time


def define_filters(rule_names, cluster_name_contains_pattern, cluster_names, image_repo_name_contains_pattern):
    event_filters = ""
    if len(rule_names) > 0:
        if len(rule_names) == 1:
            rule_filter = f'ruleName="{rule_names[0]}"'
        else:
            rules = ""
            for rule in rule_names:
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
        cluster_name_contains_pattern_filter = f'kubernetes.cluster.name contains "{cluster_name_contains_pattern}"'
        if event_filters != "":
            event_filters += "and" + cluster_name_contains_pattern_filter
        else:
            event_filters += cluster_name_contains_pattern_filter
    if image_repo_name_contains_pattern is not None:
        image_repo_name_contains_pattern_filter = f'container.image.repo contains "{image_repo_name_contains_pattern}"'
        if event_filters != "":
            event_filters += "and" + image_repo_name_contains_pattern_filter
        else:
            event_filters += image_repo_name_contains_pattern_filter
    # if event_filters == "":
    #     raise Exception("!!!No filters provided. Must include one filter!!!")
    return event_filters


def define_event_filters_with_rule_names_containing_in(rule_name, cluster_name_contains_pattern, cluster_names, image_repo_name_contains_pattern):
    event_filters = f'ruleName="{rule_name}"'
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
        cluster_name_contains_pattern_filter = f'kubernetes.cluster.name contains "{cluster_name_contains_pattern}"'
        if event_filters != "":
            event_filters += "and" + cluster_name_contains_pattern_filter
        else:
            event_filters += cluster_name_contains_pattern_filter
    if image_repo_name_contains_pattern is not None:
        image_repo_name_contains_pattern_filter = f'container.image.repo contains "{image_repo_name_contains_pattern}"'
        if event_filters != "":
            event_filters += "and" + image_repo_name_contains_pattern_filter
        else:
            event_filters += image_repo_name_contains_pattern_filter
    return event_filters

def retrieve_events_with_rule_names_containing_in(auth_header, url, ssl_verification, proxies, end_time,
                                                  start_time, event_filters):
    events_url_with_filters = url + \
        f'from={start_time}&to={end_time}&filter={event_filters}andseverity in ("0","1","2","3")'
    print("request url: ", events_url_with_filters)
    try:
        print("Retrieving events...")
        print("url with filters : ", events_url_with_filters)
        if proxies != "":
            response = requests.get(events_url_with_filters, headers=auth_header,
                                    verify=ssl_verification, proxies=proxies)
        else:
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
                f'cursor={prev_page}&filter={event_filters}andseverity in ("0","1","2","3")&limit=100'
            try:
                if proxies != "":
                    cursor_response = requests.get(events_url_with_cursor, headers=auth_header,
                                                   verify=ssl_verification, proxies=proxies)
                else:
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

def retrieve_events_with_filters(auth_header, url, ssl_verification, proxies, end_time, start_time, event_filters):
    if event_filters == "":
        events_url_with_filters = url + \
            f'from={start_time}&to={end_time}&filter=severity in ("0","1","2","3")'
    else:
        events_url_with_filters = url + \
            f'from={start_time}&to={end_time}&filter={event_filters}andseverity in ("0","1","2","3")'
    print("request url: ", events_url_with_filters)
    try:
        print("Retrieving events...")
        print("url with filters : ", events_url_with_filters)
        if proxies != "":
            response = requests.get(events_url_with_filters, headers=auth_header,
                                    verify=ssl_verification, proxies=proxies)
        else:
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
            if event_filters == "":
                events_url_with_cursor = url + \
                    f'cursor={prev_page}&filter=severity in ("0","1","2","3")&limit=100'
            else:
                events_url_with_cursor = url + \
                    f'cursor={prev_page}&filter={event_filters}andseverity in ("0","1","2","3")&limit=100'
            print("cursor event filters: ", events_url_with_cursor)
            try:
                if proxies != "":
                    cursor_response = requests.get(events_url_with_cursor, headers=auth_header,
                                                verify=ssl_verification, proxies=proxies)
                else:
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
    proxies = ""
    if (args.proxies is not None):
        print("Setting proxy...")
        proxies = set_proxy_config(args.proxies)
    end_time, start_time = retrieve_time_duration(args.time_duration)
    rule_names_containing_in, rule_names_not_containing_in = separate_rules_containing_in(args.rule_names)
    events_data = ""
    if len(rule_names_containing_in) > 0:
        for rule_name in rule_names_containing_in:
            event_filters_containing_in = define_event_filters_with_rule_names_containing_in(
                rule_name, args.cluster_name_contains_pattern, args.cluster_names, args.image_repo_name_contains_pattern)
            events_data += retrieve_events_with_rule_names_containing_in(auth_header, url, ssl_verification, proxies, end_time,
                                                                         start_time, event_filters_containing_in)
    event_filters = define_filters(
        rule_names_not_containing_in, args.cluster_name_contains_pattern, args.cluster_names, args.image_repo_name_contains_pattern)
    events_data += retrieve_events_with_filters(auth_header, url, ssl_verification, proxies, end_time,
                                  start_time, event_filters)
    write_to_output_file(events_data, args.output_file)
    print("Completed!")

if __name__ == "__main__":
    main()


