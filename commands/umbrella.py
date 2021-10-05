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
from datetime import datetime, timedelta

from requests import get, post
from requests.auth import HTTPBasicAuth
from utils import cardbuilder
from webex_bot.models.command import Command
from webex_bot.models.response import Response

log = logging.getLogger(__name__)

try:
    CLIENT_ID = os.environ["UMBRELLA_CLIENT_ID"]
    API_KEY = os.environ["UMBRELLA_API_KEY"]
    ORG_ID = os.environ["UMBRELLA_ORG_ID"]
    INVESTIGATE_KEY = os.environ["UMBRELLA_INVESTIGATE_KEY"]
except KeyError:
    log.error("Could not find Cisco Umbrella credentials.")
    log.error("Please ensure environmental variables exist: ")
    log.error("UMBRELLA_CLIENT_ID")
    log.error("UMBRELLA_API_KEY")
    log.error("UMBRELLA_ORG_ID")
    log.error("UMBRELLA_INVESTIGATE_KEY")

# API URLs
AUTH_URL = "https://management.api.umbrella.com/auth/v2/oauth2/token"
REPORT_URL = f"https://reports.api.umbrella.com/v2/organizations/{ORG_ID}"
INV_CATEGORY_URL = "https://investigate.api.umbrella.com/domains/categorization/"
INV_RISK_URL = "https://investigate.api.umbrella.com/domains/risk-score/"
INV_WHOIS_URL = "https://investigate.api.umbrella.com/whois/"


class UmbrellaEvents(Command):
    def __init__(self):
        super().__init__(
            command_keyword="umbrella events",
            help_message="Retreive Umbrella security blocks for specified time period",
            card=None,
        )
        log.info("Added command: 'umbrella events'")

    def auth(self):
        """
        Authenticate against Umbrella API, return OAuth token

        Returns:
        token - Stripped authentication token from Umbrella
        """
        body = {"grant_type": "client_credentials"}
        response = post(AUTH_URL, auth=(CLIENT_ID, API_KEY), data=body)
        token = json.loads(response.text)["access_token"]
        log.info("Umbrella auth successful")
        return token

    def execute(self, message, attachment):
        """
        Query Umbrella Reporting API for recent security events

        Parameters:
        message - Incoming webex message, with command already stripped
        attachment - Incoming attachement / action submissions from adaptive card

        Returns:
        response - Returns AdaptiveCard with list of Umbrella security events, and
                   sub-cards with event details / links.
        """
        # Check to see if lookback period specified is days or hours, then find new start time
        # Time input is accepted from user in shorthand format #h or #d (# hours or # days)
        message = message.strip()
        try:
            if "h" in message:
                # Entered lookback time was in hours
                time_window = f"-{message.split('h')[0]}hours"
            elif "d" in message:
                # Entered lookback time was in days
                time_window = f"-{message.split('d')[0]}days"
            else:
                raise (ValueError)
        except ValueError:
            # If time value isn't in the correct format (or blank) return help message
            response = (
                "Sorry, I didn't understand the time period you specified. "
                + "Please use the format 'umbrella events <time_period>' where time_period"
                + "is a lookback period from now, specified in days or hours (ex. 4d or 24h)"
            )
            return response
        # Auth against Umbrella API, get token used for future API calls
        auth_token = self.auth()
        # Query Umbrella reporting API for security events
        # NOTE: These are not all the possible Umbrella URL categories. Only included
        #       security block category for demo purposes
        url = (
            f"{REPORT_URL}/activity/dns"
            + f"?from={time_window}"
            + "&to=now&limit=100&categories=67"
        )
        headers = {"Authorization": f"Bearer {auth_token}"}
        log.info("Checking for Umbrella security events...")
        response = get(url, headers=headers)
        events = json.loads(response.text)
        count = len(events)
        log.info(f"Got {count} Umbrella events")
        if count == 0:
            return "No events found during the specified window."

        # Generate card & post response to chat
        card = cardbuilder.buildUmbrellaEventsCard(ORG_ID, events)
        response = Response()
        response.text = "Umbrella events found"
        response.attachments = card

        return response


class UmbrellaInvestigate(Command):
    def __init__(self):
        super().__init__(
            command_keyword="umbrella investigate",
            help_message="Retreive Umbrella investigate data for a given URL",
            card=None,
        )
        log.info("Added command: 'umbrella investigate'")

    def execute(self, message, attachment):
        """
        Retrieve data from Umbrella investigate info for a given URL in message.
        To assemble response, we pull info from WHOIS, Risk score, and URL
        categorization APIs.

        Parameters:
        message - Incoming webex message, with command already stripped
        attachment - Incoming attachement / action submissions from adaptive card

        Returns:
        response - Returns AdaptiveCard with detailed info on a single URL
                   pulled from Umbrella Investigate
        """
        # Build new dictionary to hold domain info we collect
        domain_data = {}
        headers = {"Authorization": f"Bearer {INVESTIGATE_KEY}"}
        url = message.strip()
        domain_data["url"] = url
        log.info(f"Checking Umbrella investigate for url: {url}")

        # Pull domain risk score
        risk = get(INV_RISK_URL + url, headers=headers)
        try:
            domain_data["risk_score"] = json.loads(risk.text)["risk_score"]
        except IndexError:
            response = "Sorry, that URL was not found"
            return response

        # Pull domain categorizations
        category = get(INV_CATEGORY_URL + url + "?showLabels", headers=headers)
        domain_data["security_categories"] = json.loads(category.text)[url][
            "security_categories"
        ]
        domain_data["content_categories"] = json.loads(category.text)[url][
            "content_categories"
        ]

        # Pull WHOIS data for the domain
        whois = json.loads(get(INV_WHOIS_URL + url, headers=headers).text)
        domain_data["registrar"] = whois["registrarName"]
        domain_data["created"] = whois["created"]
        domain_data["expires"] = whois["expires"]

        # Generate card & post response to chat
        card = cardbuilder.buildUmbrellaInvestigateCard(domain_data)
        response = Response()
        response.text = f"Investigate data for {url}"
        response.attachments = card

        return response
