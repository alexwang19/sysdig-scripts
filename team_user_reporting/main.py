import requests
import json
import csv
import argparse


def retrieve_set_sysdig_params():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", dest='sysdig_base_url', type=str,
                        help="Base url of sysdig. ex: us2.app.sysdig.com")
    parser.add_argument("--api-token", dest='sysdig_api_token',
                        type=str, help="Sysdig API Token")
    parser.add_argument("--csv-file-name", dest='csv_file_name',
                        type=str, help="Filename of csv")
    return parser.parse_args()


def retrieve_sysdig_header_url(args):
    auth_token = args.sysdig_api_token
    auth_header = {'Authorization': 'Bearer ' + auth_token}
    base_url = args.sysdig_base_url.replace("https://", "")
    url = f'https://{base_url}/api/teams'
    return auth_header, url

def main():
    args = retrieve_set_sysdig_params()
    auth_header, url = retrieve_sysdig_header_url(args)

    response = requests.get(url, headers=auth_header)
    data = json.loads(json.dumps(response.json()))

    teams = data['teams']

    with open(args.csv_file_name, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        csv_writer.writerow(['Team Name', 'User ID', 'Username'])

        teams = data['teams']

        for team in teams:
            team_name = team['name']
            for user_role in team['userRoles']:
                user_id = user_role['userId']
                user_name = user_role['userName']

                csv_writer.writerow([team_name, user_id, user_name])

    print(f"CSV file '{args.csv_file_name}' has been created.")


if __name__ == "__main__":
    main()