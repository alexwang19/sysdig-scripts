import csv
import requests
import argparse
import os
import time

def retrieve_set_sysdig_params():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", dest='sysdig_base_url', type=str,
                        help="Base url of sysdig. ex: us2.app.sysdig.com")
    parser.add_argument("--api-token", dest='sysdig_api_token',
                        type=str, help="Sysdig API Token")
    parser.add_argument("--acceptance-files-directory", dest='acceptance_files_directory',
                        type=str, help="Full path to directory containing csv files for acceptance")
    parser.add_argument("--ssl-verification", dest='ssl_verification',
                        type=str, help="enabled or disabled for values. Default is disabled.")
    return parser.parse_args()

def retrieve_sysdig_header_url(args):
    auth_token = args.sysdig_api_token
    auth_header = {'Authorization': 'Bearer ' + auth_token}
    base_url = args.sysdig_base_url.replace("https://", "")
    url = f'https://{base_url}/api/scanning/riskmanager/v2/definitions'
    return auth_header, url


def delete_risk_acceptance(auth_header, url, ssl_verification, directory_path):
    existing_risk_exceptions = []
    response = requests.get(url, headers=auth_header, params={'limit': 100})
    existing_risk_exceptions.append((response.json()['data']))

    while (response.json()['page']['next'] != ""):
        response = requests.get(url, headers=auth_header, params={
            'cursor': response.json()['page']['next'], 'limit': 100})
        existing_risk_exceptions.append(response.json()['data'])

    for csv_data in os.listdir(directory_path):
        filename_with_path = f'{directory_path}/' + csv_data
        if os.path.isfile(filename_with_path):
            with open(filename_with_path) as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                line_count = 0
                for row in csv_reader:
                    if line_count == 0:
                        print(f'Column names are {", ".join(row)}')
                        line_count += 1
                    else:
                        for existing_risk_exception in existing_risk_exceptions:
                            for risk_exception in existing_risk_exception:
                                url_with_risk_def = url + "/" + \
                                    risk_exception['riskAcceptanceDefinitionID']
                                if risk_exception['entityValue'] == row[0]:
                                    if risk_exception['context']:
                                        if risk_exception['context'][0]['contextType'] == row[4]:
                                            if risk_exception['context'][0]['contextValue'] == row[5]:
                                                try:
                                                    print("Delete risk acceptance: ", risk_exception)
                                                    response = requests.delete(
                                                        url_with_risk_def, json=risk_exception, headers=auth_header)
                                                    print(response.status_code)
                                                except requests.exceptions.HTTPError as e:
                                                    print(" ERROR ".center(80, "-"))
                                                    print("Failed deleting risk acceptance", e)
                                                    print(response.text)
                                                except requests.exceptions.RequestException as e:
                                                    print(" ERROR ".center(80, "-"))
                                                    print(e, "Failed deleting risk acceptance")
                                                if line_count % 70 == 0:
                                                    print("Sleep 20 secs after ",
                                                            line_count, " requests...")
                                                    time.sleep(20)
                                                line_count += 1
    print("Finished deletion")

def main():
    args = retrieve_set_sysdig_params()
    auth_header, url = retrieve_sysdig_header_url(args)
    ssl_verification = False
    if (args.ssl_verification == "enabled"):
        ssl_verification = True
    delete_risk_acceptance(auth_header, url, ssl_verification,
                           args.acceptance_files_directory)


if __name__ == "__main__":
    main()