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
from base64 import b64encode
from datetime import datetime, timedelta

from requests import get
from requests.auth import HTTPBasicAuth
from utils import cardbuilder
from webex_bot.models.command import Command
from webex_bot.models.response import Response

log = logging.getLogger(__name__)


try:
    CLIENT_ID = os.environ["AMP4E_CLIENT_ID"]
    API_KEY = os.environ["AMP4E_API_KEY"]
except KeyError:
    log.error("Could not find Cisco Secure Endpoint credentials.")
    log.error("Please ensure environmental variables exist: ")
    log.error("AMP4E_CLIENT_ID")
    log.error("AMP4E_API_KEY")

BASE_URL = "https://api.amp.cisco.com/v1/"


class AmpEvents(Command):
    def __init__(self):
        super().__init__(
            command_keyword="amp events",
            help_message="Retrieve a list of recent AMP events within a recent time period (ex. 4h or 3d)",
            card=None,
        )
        log.info("Added command: 'amp events'")

    def execute(self, message, attachment):
        """
        Queries recent threat detection events from AMP and returns list of events
        Requires a lookback period to be specified for how far back to search

        Parameters:
        message - Incoming webex message, with command already stripped
        attachment - Incoming attachement / action submissions from adaptive card

        Returns:
        response - Returns an AdaptiveCard object containing AMP detection events,
                   which is then sent back to the requesting user. Card contains
                   sub-card for each event with event details & links to AMP dashboard
        """
        # Check to see if lookback period specified is days or hours, then find new start time.
        # Time input is accepted from user in shorthand format #h or #d (# hours or # days)
        message = message.strip()
        try:
            if "h" in message:
                # Entered lookback time was in hours
                time_window = datetime.today() - timedelta(
                    hours=int(message.split("h")[0])
                )
            elif "d" in message:
                # Entered lookback time was in days
                time_window = datetime.today() - timedelta(
                    days=int(message.split("d")[0])
                )
            else:
                raise (ValueError)
        except ValueError:
            # If time value isn't in the correct format (or blank) return help message
            log.error(f"Invalid lookback period specified: {message}")
            response = (
                "Sorry, I didn't understand the time period you specified. "
                + "Please use the format 'amp events <time_period>' where time_period"
                + "is a lookback period from now, specified in days or hours (ex. 4d or 24h)"
            )
            return response
        log.info(f"Looking for AMP events generated since {time_window.isoformat()}")
        # Assemble event lookup URL, using most common event types for malware detection
        # NOTE: These are not all the possible AMP detection events. Included common
        #       event types for demo purposes
        url = (
            f"{BASE_URL}/events?"
            f"start_date={time_window.isoformat()}"
            "&limit=100"
            "&event_type[]=1090519054"
            "&event_type[]=1090519081"
            "&event_type[]=553648147&"
        )
        # Retrieve AMP event data
        response = get(url, auth=(CLIENT_ID, API_KEY))
        events = json.loads(response.text)["data"]
        count = len(events)

        log.info(f"Detected {count} recent events.")
        if count == 0:
            return "No events found during the specified window."
        # Generate card & post response to chat
        card = cardbuilder.buildAMPEventsCard(events)
        response = Response()
        response.text = "AMP events found"
        response.attachments = card

        return response
