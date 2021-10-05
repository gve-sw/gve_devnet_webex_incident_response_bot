'''
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
               
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
'''

import json
import logging
import os

from requests import auth, get, post
from requests.auth import HTTPBasicAuth
from utils import cardbuilder
from webex_bot.models.command import Command
from webex_bot.models.response import Response

log = logging.getLogger(__name__)

try:
    IPR_USER = os.environ["SPAMHAUS_USER"]
    IPR_PASS = os.environ["SPAMHAUS_PASS"]
except KeyError:
    log.error("Could not find SpamHaus Intelligence API credentials.")
    log.error("Please ensure environmental variables exist: ")
    log.error("SPAMHAUS_USER")
    log.error("SPAMHAUS_PASS")
    

BASE_URL = "https://api.spamhaus.org/api/intel/v1/byobject/cidr/XBL/listed/history/"
LOGIN_URL = "https://api.spamhaus.org/api/v1/login"

LOGIN_HEADER = {"username": IPR_USER, "password": IPR_PASS, "realm": "intel"}


class IPReputation(Command):
    def __init__(self):
        super().__init__(
            command_keyword="ip lookup",
            help_message="Retreieve SpamHaus reputation details for a specified IP address",
            card=None,
        )
        log.info("Added command: 'ip lookup'")

    def execute(self, message, attachment):
        """
        Upon receiving IP address from user, reach out to SpamHaus to get reputation details

        Parameters:
        message - Incoming webex message, with command already stripped
        attachment - Incoming attachement / action submissions from adaptive card

        Returns:
        response - Returns AdaptiveCard containing IP address reputation data
        """
        ip_addr = message.strip()
        response = Response()

        # Get authentication token
        auth_response = post(LOGIN_URL, json=LOGIN_HEADER)
        auth_token = json.loads(auth_response.text)["token"]
        auth_header = {"Authorization": f"Bearer {auth_token}"}

        # Query IP reputation API
        ip_response = get(BASE_URL + ip_addr + "?limit=5", headers=auth_header)

        # Spamhaus returns 404 if there is no data available
        if ip_response.status_code == 404:
            response.text = "Sorry, no reputation data was found for that IP address!"
            return response

        ip_data = json.loads(ip_response.text)["results"]

        # Generate card & post response to chat
        card = cardbuilder.buildIPReputationCard(ip_data)
        response = Response()
        response.text = f"IP Reputation data for {ip_addr}"
        response.attachments = card

        return response
