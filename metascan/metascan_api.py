import requests
import time
import json
from lib.common.out import print_error

__author__ = 'Josh Maine'


class MetaScan():
    """ This is for our 30 day trial it only allows one session connection at a time."""

    def __init__(self, ip, port, apikey=''):
        self.ip = ip
        self.port = port
        self.apikey = apikey
        self.connected = True
        try:
            requests.get(url='http://{0}:{1}/metascan_rest/stat'.format(self.ip, self.port), timeout=5)
        except requests.exceptions.Timeout:
            print_error("Could not connect to Metascan Server.")
            print_error("Could not connect to Metascan Server.")
            self.connected = False
        except requests.exceptions.RequestException as e:
            print_error("Metascan Error: {}".format(e))

    def scan_file(self, this_file, filename='', archivepwd=''):
        url = 'http://{0}:{1}/metascan_rest/file'.format(self.ip, self.port)
        params = dict(apikey=self.apikey, filename=filename, archivepwd=archivepwd)
        with open(this_file, 'rb') as f:
            sample = f.read()
        return requests.post(url=url, data=sample, params=params)

    def scan_file_stream(self, this_file_stream, filename='', archivepwd=''):
        url = 'http://{0}:{1}/metascan_rest/file'.format(self.ip, self.port)
        params = dict(apikey=self.apikey, filename=filename, archivepwd=archivepwd)
        return requests.post(url=url, data=this_file_stream, params=params)

    def get_scan_results_by_data_id(self, data_id):
        url = 'http://{0}:{1}/metascan_rest/file/{2}'.format(self.ip, self.port, data_id)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_scan_results_without_fileinfo(self, data_id):
        url = 'http://{0}:{1}/metascan_rest/file/{2}/scanresult'.format(self.ip, self.port, data_id)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_scan_results_by_hash(self, this_hash):
        url = 'http://{0}:{1}/metascan_rest/hash/{2}'.format(self.ip, self.port, this_hash)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def rescan_file(self, file_id, filename='', archivepwd='', source_ip='', forcerescan=1):
        """
        Rescanning a file

        @param file_id: Get from retrieving scan results - REQUIRED
        @param apikey: API key assigned by user - OPTIONAL
        @param filename: Name of files to preserve extension during scan and meta data - OPTIONAL
        @param archivepwd: If submitted file is password protected archive - OPTIONAL
        @param source_ip: ip address or identifier of host machine - OPTIONAL
        @param forcerescan: 1: rescan even if rescan_available flag is marked as true. - RECOMMENDED
                               This is useful for sanity check scan
        @return: data_id - Data ID used for retreiving scan result
        """
        url = 'http://{0}:{1}/metascan_rest/rescan/{2}'.format(self.ip, self.port, file_id)
        params = dict(apikey=self.apikey, filename=filename, archivepwd=archivepwd, source=source_ip,
                      forcerescan=forcerescan)
        return requests.get(url=url, params=params)

    def download_file(self, file_id):
        url = 'http://{0}:{1}/metascan_rest/file/download/{2}'.format(self.ip, self.port, file_id)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_latest_scan_results(self, file_id):
        url = 'http://{0}:{1}/metascan_rest/lastest/{2}'.format(self.ip, self.port, file_id)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_engine_result(self, data_id, engine_id):
        url = 'http://{0}:{1}/metascan_rest/file/{2}/scanresult/{3}'.format(self.ip, self.port, data_id, engine_id)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_file_info(self, data_id):
        url = 'http://{0}:{1}/metascan_rest/file/{2}/fileinfo'.format(self.ip, self.port, data_id)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_queue_length(self):
        url = 'http://{0}:{1}/metascan_rest/file/inqueue'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def scan_file_and_get_results(self, this_file):
        response = self.scan_file(this_file, self.apikey)
        if response.status_code == requests.codes.ok:
            data_id = response.json()['data_id']
            while True:
                response = self.get_scan_results_by_data_id(data_id=data_id)
                if response.status_code != requests.codes.ok:
                    return response
                if response.json()['scan_results']['progress_percentage'] == 100:
                    break
                else:
                    time.sleep(3)
            # print json.dumps(response.json(), sort_keys=False, indent=4)
        return response

    def scan_file_stream_and_get_results(self, this_stream):
        response = self.scan_file_stream(this_file_stream=this_stream)
        if response.status_code == requests.codes.ok:
            data_id = response.json()['data_id']
            while True:
                response = self.get_scan_results_by_data_id(data_id=data_id)
                if response.status_code != requests.codes.ok:
                    return response
                if response.json()['scan_results']['progress_percentage'] == 100:
                    break
                else:
                    time.sleep(3)
            # print json.dumps(response.json(), sort_keys=False, indent=4)
        return response

        # #: Helper function for old API that returned XML
        # def json_response(self, response, pretty=True):
        #     if pretty:
        #         return json.dumps(xmltodict.parse(response.content), sort_keys=False, indent=4)
        #     else:
        #         return json.dumps(xmltodict.parse(response.content))
        #
        # #: Helper function for old API that returned XML
        # def dict_response(self, response):
        #     data = []
        #     root = etree.fromstring(response.content)
        #     for result in root.xpath('//engine_result'):
        #         engine_result = {}
        #         for engine in result.getchildren():
        #             if 'engine_name' in engine.tag:
        #                 engine_result[engine.tag]=engine.text.replace(' scan engine', '')
        #             elif 'scan_result' in engine.tag:
        #                 engine_result[engine.tag]=int(engine.text)
        #             else:
        #                 engine_result[engine.tag]=engine.text
        #         data.append(engine_result)
        #     return data


class Admin():
    """ This is for our 30 day trial it only allows one session connection at a time."""

    def __init__(self, ip, port, apikey=''):
        self.ip = ip
        self.port = port
        self.apikey = apikey

    def get_stat(self):
        url = 'http://{0}:{1}/metascan_rest/stat'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    #
    # http://localhost:8008/metascan_rest/stat/scanhistory/<n hour>
    #
    # http://localhost:8008/metascan_rest/stat/clients/<n hour>
    #
    # http://localhost:8008/metascan_rest/stat/fileuploads
    #
    # http://localhost:8008/metascan_rest/stat/fileuploads/last
    #
    # http://localhost:8008/metascan_rest/stat/apikeys/<n day>

    #: Get the lastest 30 day stats
    def get_file_types(self):
        url = 'http://{0}:{1}/metascan_rest/stat/filetypes'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_server_health(self):
        url = 'http://{0}:{1}/metascan_rest/stat/serverhealth'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    # http://localhost:8008/metascan_rest/stat/threats
    #
    def get_engines(self):
        url = 'http://{0}:{1}/metascan_rest/stat/engines'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    def get_engine_defs(self):
        url = 'http://{0}:{1}/metascan_rest/stat/enginedef'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

    # http://localhost:8008/metascan_rest/admin/prop
    #
    # http://localhost:8008/metascan_rest/admin/license
    #
    # http://localhost:8008/metascan_rest/admin/license/activateonline
    #
    # http://localhost:8008/metascan_rest/admin/license/activateoffline
    #
    # http://localhost:8008/metascan_rest/admin/reload/all

    def get_update_progress(self, engine_name):
        url = 'http://{0}:{1}/metascan_rest/admin/update'.format(self.ip, self.port)
        data = dict(engine=engine_name)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, data=json.dumps(data), params=params)

    def update_engine(self, engine_name):
        url = 'http://{0}:{1}/metascan_rest/admin/update'.format(self.ip, self.port)
        data = dict(engine=engine_name)
        params = dict(apikey=self.apikey)
        return requests.post(url=url, data=json.dumps(data), params=params)

    # http://localhost:8008/metascan_rest/admin/offlineupdate/<job ID>
    #
    # http://localhost:8008/metascan_rest/admin/avs

    def get_avs(self):
        url = 'http://{0}:{1}/metascan_rest/admin/avs'.format(self.ip, self.port)
        params = dict(apikey=self.apikey)
        return requests.get(url=url, params=params)

# http://localhost:8008/metascan_rest/admin/sibling
#
# http://localhost:8008/metascan_rest/admin/sibling/add
#
# http://localhost:8008/metascan_rest/admin/sibling/remove
#
# http://localhost:8008/metascan_rest/admin/broadcast/addsibling
#
# http://localhost:8008/metascan_rest/admin/broadcast/removesibling
#
# http://localhost:8008/metascan_rest/admin/logs/events/0/0
#
# http://localhost:8008/metascan_rest/admin/logs/files/0/0
#
# http://localhost:8008/metascan_rest/admin/logs/windowsevent/0/0
#
# http://localhost:8008/metascan_rest/admin/logs/events/clear
#
# http://localhost:8008/metascan_rest/admin/logs/files/clear
#
# http://localhost:8008/metascan_rest/admin/logs/stats/clear
#
# http://localhost:8008/metascan_rest/admin/postprocessing
#
# http://localhost:8008/metascan_rest/admin/config/proxy



































