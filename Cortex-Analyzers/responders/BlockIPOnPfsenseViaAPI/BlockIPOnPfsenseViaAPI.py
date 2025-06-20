#!/usr/bin/env python3
# encoding: utf-8

import requests
import traceback
import datetime
from cortexutils.responder import Responder
import base64

class BlockIPOnPfSense(Responder):

    def __init__(self):
        Responder.__init__(self)
        self.pfsense_url = self.get_param('config.pfsense_url', None, 'Missing pfSense URL')
        self.pfsense_user = self.get_param('config.username', None, 'Missing pfSense username')
        self.pfsense_pass = self.get_param('config.password', None, 'Missing pfSense password')
        self.data_type = self.get_param('data.dataType')
        self.time = ''

        if self.data_type == 'ip':
            self.ip_to_block = self.get_param('data.data', None, 'No IP Address supplied')
        else:
            self.error("Unsupported data type: must be IP")

    def run(self):
        try:
            # Encode Basic Auth header manually
            basic_auth_str = f"{self.pfsense_user}:{self.pfsense_pass}"
            basic_auth_bytes = base64.b64encode(basic_auth_str.encode()).decode()

            payload = {
                "type": "block",
                "interface": ["wan"],
                "ipprotocol": "inet",
                "protocol": "tcp/udp",  # or udp, tcp/udp
                "source": self.ip_to_block,
                "destination": "any",
                "descr": f"Blocked by Cortex",
                "disabled": False,
                "log": False,
                "statetype": "keep state",
                "floating": False,
                "quick": False,
                "direction": "in"
            }

            endpoint = f"{self.pfsense_url}/api/v2/firewall/rule"
            headers = {
                "Authorization": f"Basic {basic_auth_bytes}",
                "Content-Type": "application/json"
            }

            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                verify=False  # disable SSL verification if self-signed certs
            )

            if response.status_code in [200, 201]:
                self.time = datetime.datetime.utcnow().isoformat()
                self.report({"message": f"IP {self.ip_to_block} blocked successfully at {self.time}"})
            else:
                try:
                    error_detail = response.json()
                except Exception:
                    error_detail = response.text
                self.error(f"Failed to block IP. Status: {error_detail}")
        except Exception:
            self.error(traceback.format_exc())


if __name__ == "__main__":
    BlockIPOnPfSense().run()
