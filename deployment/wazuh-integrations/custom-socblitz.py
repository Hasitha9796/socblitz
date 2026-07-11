# SocBlitz custom integration.
# Forwards the raw Wazuh alert JSON to the SocBlitz SOAR webhook, unmodified.
# The <level> threshold in ossec.conf gates what ever reaches this script.
#
# ossec.conf:
# <integration>
#   <name>custom-socblitz</name>
#   <hook_url>http://socblitz-backend:5000/api/v1/soar/trigger/wazuh-alert</hook_url>
#   <level>12</level>
#   <alert_format>json</alert_format>
# </integration>

import json
import os
import sys

try:
    import requests
except ModuleNotFoundError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'

ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(args) > 4 else '', args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            with open(LOG_FILE, 'a') as f:
                f.write('# ERROR: Wrong arguments\n')
            sys.exit(ERR_BAD_ARGUMENTS)

        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        process_args(args)
    except Exception as e:
        debug(str(e))
        raise


def process_args(args):
    alert_file_location = args[ALERT_INDEX]
    webhook = args[WEBHOOK_INDEX]

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Sending alert {json_alert.get('id')} (level {json_alert.get('rule', {}).get('level')}) to {webhook}")

    send_msg(json_alert, webhook)


def debug(msg):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def send_msg(alert, url):
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    try:
        res = requests.post(url, data=json.dumps(alert), headers=headers, timeout=10)
        debug(f'# Response received: {res.status_code}')
    except Exception as e:
        debug(f'# ERROR sending to SocBlitz: {e}')


def get_json_alert(file_location):
    try:
        with open(file_location) as f:
            return json.load(f)
    except FileNotFoundError:
        debug(f"# JSON file for alert {file_location} doesn't exist")
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug(f'Failed getting JSON alert. Error: {e}')
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
