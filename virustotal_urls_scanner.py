import argparse
import json
import requests
import time


def get_virustotal_data(url_list, key):
    virustotal_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    urls_data = []
    for url in url_list:
        params = {'apikey': key, 'resource': url}
        url_report = requests.get(virustotal_url, params=params)
        urls_data.append(url_report.json())
    return urls_data


def require_updating(url):
    # not ready yet: looks for the last_modified value of the url in the db
    # and returns 'true' if more than 30 min passed since current_time
    need_update = True  # temporary
    return need_update


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input_urls', help="full-path to urls csv")
    parser.add_argument('-o', '--output_data', help="full path to the extracted data file (list of JSONs)")
    parser.add_argument('-k', '--api_key', help='VirusTotal API key')
    args = parser.parse_args()

    input_urls, url_jsons_output, api_key = args.input_urls, open(args.output_data, 'a'), args.api_key

    external_query_list = []
    internal_query_list = []
    with open(input_urls) as f:
        for line in f:
            if require_updating(line):
                external_query_list.append(line.rstrip())
            else:
                internal_query_list.append(line.rstrip())

        url_jsons_list = []
        for i in range(len(external_query_list)):
            if i % 4 == 0:  # up to 4 urls per minute for non-commercial users...
                time.sleep(60)
                current_batch = []
            current_batch.append(external_query_list[i])
            if i % 4 == 3 or i == len(external_query_list) - 1:
                url_jsons_list += get_virustotal_data(current_batch, api_key)
        for row in url_jsons_list:
            json.dump(row, url_jsons_output)
            url_jsons_output.write("\n")

        # not implemented yet:
        # db_results = get_db_report(internal_query_list, db_credentials)  # get reports for sites from self-db
        # update self-db with reports from sites in the 'external_query_list'
