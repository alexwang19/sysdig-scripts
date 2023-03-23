import csv
import requests
import sys
import os
import datetime
from datetime import timezone


# SYSDIG API TOKEN
auth_token = 'xxxxxx-xxxxx-xxxxxx'
auth_header = {'Authorization': 'Bearer ' + auth_token}
vulnerability_exception_default_list = "global"
# SYSDIG URL - INSERT APPROPRIATE SYSDIG URL POINTING TO CORRECT REGION
url = f'https://us2.app.sysdig.com/api/scanning/v1/vulnexceptions/{vulnerability_exception_default_list}'

# SSL VERIFICATION
ssl_verification_flag=False

def retrieve_existing_exceptions():
    existing_risk_exceptions = []
    existing_cve_exceptions = []

    try:
        response = requests.get(
            url, headers=auth_header, verify=ssl_verification_flag)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(" ERROR ".center(80, "-"))
        print(e)
    except requests.exceptions.RequestException as e:
        print(e)
    existing_risk_exceptions.append((response.json()['items']))

    # while (response.json()['page']['next'] != ""):
    #     try:
    #         response = requests.get(url, headers=auth_header, params={
    #             'cursor': response.json()['page']['next'], 'limit': 100})
    #         response.raise_for_status()
    #     except requests.exceptions.HTTPError as e:
    #         print(" ERROR ".center(80, "-"))
    #         print(e)
    #     except requests.exceptions.RequestException as e:
    #         print(e)
    #     existing_risk_exceptions.append(response.json()['data'])

    for existing_risk_exception in existing_risk_exceptions:
        for risk_exception in existing_risk_exception:
            # print(risk_exception['trigger_id'])
            existing_cve_exceptions.append(risk_exception['trigger_id'])
    return existing_risk_exceptions, existing_cve_exceptions

def validate_date_format(date_text):
    try:
        datetime.date.fromisoformat(date_text)
    except ValueError:
        raise ValueError("Incorrect data format, should be YYYY-MM-DD")

def convert_time_to_epoch(expiration_date, cve):
    validate_date_format(expiration_date)
    date = expiration_date.split('-')
    dt = datetime.datetime(int(date[0]), int(
        date[1]), int(date[2]), 0, 0)
    present = datetime.datetime.now()
    if dt < present:
        print("Time is in the past!Please fix and try again for cve: ", cve)
        sys.exit()
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def add_vulnerability_exception(cve_dups, cve, expiration_date, notes):
    print("Adding new exception for :", cve)
    cve_dups.append(cve)
    date = convert_time_to_epoch(expiration_date, cve)
    vuln_exception = {"gate": "vulnerabilities", "trigger_id": cve,
                      "expiration_date": date, "notes": notes}
    post_method(vuln_exception)
    return cve_dups

def post_method(vuln_exception):
    try:
        print("Adding new risk exceptions")
        print(vuln_exception)
        post_url = url + "/vulnerabilities"
        response = requests.post(
            post_url, json=vuln_exception, headers=auth_header, verify=ssl_verification_flag)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(" ERROR ".center(80, "-"))
        print("Failed adding new risk acceptance", e)
    except requests.exceptions.RequestException as e:
        print(" ERROR ".center(80, "-"))
        print(e, "Failed adding new risk acceptance")

def determine_exception_changes(existing_risk_exceptions, cve, expiration_date, notes):
    change_detected = False
    for existing_risk_exception in existing_risk_exceptions:
        for risk_exception in existing_risk_exception:
            new_expiration = risk_exception['expiration_date']
            appended_note = risk_exception['notes']
            date = convert_time_to_epoch(expiration_date, cve)
            if cve == risk_exception['trigger_id']:
                if date != risk_exception['expiration_date']:
                    new_expiration = date
                    change_detected = True
                if risk_exception['notes'] == None and notes != "":
                    appended_note = notes
                    change_detected = True
                if risk_exception['notes'] != None:
                    if notes != risk_exception['notes']:
                        print("Appending note for CVE: ",
                            risk_exception['trigger_id'])
                        appended_note = risk_exception['notes'] + \
                            notes
                        change_detected = True
                if change_detected:
                    updated_risk_exception = {"gate": "vulnerabilities", "trigger_id": cve,
                                              "expiration_date": new_expiration, "notes": appended_note}
                    updated_url = url + "/vulnerabilities/" + \
                        risk_exception['id']
                    try:
                        print("Updating CVE: ", cve)
                        response = requests.put(
                            updated_url, json=updated_risk_exception, headers=auth_header, verify=ssl_verification_flag)
                        response.raise_for_status()
                    except requests.exceptions.HTTPError as e:
                        print(" ERROR ".center(80, "-"), "CVE:", cve)
                        print("Failed updating cve", e)
                    except requests.exceptions.RequestException as e:
                        print(" ERROR ".center(80, "-"), "CVE:", cve)
                        print(e, "Failed updating cve")


def process_exceptions():
    # ADD LIST OF FILES HERE
    directory_path = "cve_acceptance_files"
    existing_risk_exceptions, existing_cve_exceptions = retrieve_existing_exceptions()
    for csv_data in os.listdir(directory_path):
        try:
            filename_with_path = f'{directory_path}/' + csv_data
            with open(filename_with_path) as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                line_count = 0
                cve_dups = []
                for row in csv_reader:
                    cve = row[0] + "+*"
                    expiration_date = row[1]
                    notes = row[2]
                    if line_count == 0:
                        print(f'Column names are {", ".join(row)}')
                        line_count += 1
                    else:
                        if cve not in cve_dups:
                            if cve not in existing_cve_exceptions:
                                cve_dups = add_vulnerability_exception(
                                    cve_dups, cve, expiration_date, notes)
                            else:
                                determine_exception_changes(
                                    existing_risk_exceptions, cve, expiration_date, notes)
                        else:
                            print("Found duplicate CVE in CSV file: ", cve)
                        line_count += 1
                print(f'Processed {line_count} lines.')
        except OSError as e:
            print("FILE NOT FOUND".center(80, "-"))
            print(e)
            sys.exit()
    print("Done processing file: ", filename_with_path)


process_exceptions()
