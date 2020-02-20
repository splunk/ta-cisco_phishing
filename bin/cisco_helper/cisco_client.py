from datetime import datetime, timedelta
import http.client
import json
import time


class CiscoClient(object):
    _cisco_token_url = '/oauth/token'
    _cisco_messages_url = '/v1/messages'

    def __init__(self, configs):
        self._token = None
        self._message_limit = int(configs['message_limit'])
        self._duration = int(configs['duration'])
        self._client_id = configs['client_id']
        self._cisco_token_host = configs['cisco_token_host']
        self._cisco_service_host = configs['cisco_service_host']
        self._secret = configs['client_secret']
        self._token = self.get_token()

    def get_messages(self, initial_time):
        has_more = True
        offset = 0
        while has_more:
            message_page = self.get_page(offset, initial_time)
            if message_page and message_page.get('messages', None):
                for data in message_page['messages']:
                    yield data

            if message_page is not None:
                has_more = message_page['count'] >= self._message_limit
                offset = message_page['offset'] + message_page['count']
            else:
                has_more = False

    def get_page(self, offset, initial_time):
        start_time, end_time = self.get_start_end_date(initial_time)
        if self._token is None:
            raise Exception('Cisco phishing token not found.')

        headers = {'Authorization': 'Bearer ' + self._token}
        conn = http.client.HTTPSConnection(self._cisco_service_host)

        message_url = (self._cisco_messages_url + '?start_date=%s&end_date=%s&limit=%d&offset=%d&sort=date+asc' %
            (start_time, end_time, self._message_limit, offset))

        conn.request("GET", message_url, headers=headers)
        res = conn.getresponse()

        while res.status == 429:  # if getting too many requests error, run it again after 1 second
            time.sleep(1)
            conn.request("GET", message_url, headers=headers)
            res = conn.getresponse()

        if res.status == 200:
            data = res.read()
            out = data.decode("utf-8")
            parsed = json.loads(out)

            return parsed
        elif res.status == 401:  # if getting unauthorized response, throw exception.
            raise Exception('Cisco client Error: server returns unauthorized response. ' + str(res.msg))
        else:
            raise Exception('Cisco client Error: there is a problem connecting to cisco api. ' + str(res.msg))

    def get_token(self):
        if self._token is None:
            post_body = {
                'client_id': self._client_id,
                'client_secret': self._secret
            }
            json_data = json.dumps(post_body)

            headers = {'content-type': 'application/json'}
            conn = http.client.HTTPSConnection(self._cisco_token_host)

            conn.request("POST",
                         self._cisco_token_url,
                         json_data,
                         headers=headers)
            tk = conn.getresponse()
            if tk.status == 200:
                data = tk.read()
                out = data.decode("utf-8")
                parsed = json.loads(out)

                return parsed['access_token']
            else:
                raise Exception(
                    'Cisco client Error: unable to obtain token from cisco api. '
                    + str(tk.msg))

    def get_start_end_date(self, initial_time):
        start_time = initial_time.isoformat()
        end_time = (datetime.utcnow() - timedelta(minutes=self._duration)).isoformat()
        # cisco api only limits time range to two months, if time range is wider than 30 days
        # change the end time to current time + 30 days
        if (datetime.utcnow() - initial_time).days > 30:
            # just add 30 days at a time
            end_time = (initial_time + timedelta(days=30)).isoformat()

        return start_time, end_time
