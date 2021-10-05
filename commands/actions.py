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

from requests import get, put
from requests.auth import HTTPBasicAuth
from utils import cardbuilder, mail
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


class ContainmentActions(Command):
    def __init__(self):
        super().__init__(
            command_keyword="actions",
            help_message="See potential actions to take against a compromised computer",
            card=None,
        )
        log.info("Added command: 'actions'")

    def execute(self, message, attachment=None):
        """
        Handle request to execute actions against a target PC

        Parameters:
        message - Incoming webex message, with command already stripped
        attachment - Incoming attachement / action submissions from adaptive card

        Returns:
        response - If message received with command (ex. actions TEST-PC-1),
                   then return an adaptive card that shows actions to take against that PC.
                   If message is received with attachment, we assume user submitted action
                   from adaptive card buttons. Take actions following what user selected.
        """
        response = Response()
        try:
            # If message contains a card submission, then process what action was requested
            if attachment.type == "submit":
                if attachment.inputs["requested_action"] == "quarantine":
                    response = self.quarantineSystem(
                        attachment.inputs["target_computer"]
                    )
                if attachment.inputs["requested_action"] == "notify user":
                    mail.sendMail(
                        attachment.inputs["target_computer"],
                        attachment.inputs["user_email_addr"],
                    )
                    response.text = (
                        f"Message sent to {attachment.inputs['user_email_addr']}!"
                    )
        except AttributeError:
            # If not a card submission, send card to prompt for action
            if message == "":
                # Send error message if we didn't get a computer name
                response.text = (
                    "Please provide a computer name (format: actions <computername>)"
                )
                return response
            # Send card with available containment actions
            card = cardbuilder.sendContainmentActions(message)
            # Card fallback text
            response.text = "Containment Actions"
            response.attachments = card

        return response

    def quarantineSystem(self, computer):
        """
        Look up GUID of target computer, then execute request to isolate against AMP API

        Parameters:
        computer - Hostname of target PC to take action against

        Returns:
        response - Parsed text response of isolation request
        """
        response = Response()
        computer_url = BASE_URL + f"/computers?hostname%5B%5D={computer.strip()}"

        # Get computer by hostname, retrieve connector GUID
        computers = get(computer_url, auth=(CLIENT_ID, API_KEY))
        try:
            computer_guid = json.loads(computers.text)["data"][0]["connector_guid"]
        except IndexError:
            response.text = "Sorry, I couldn't find that computer."
            return response

        # Send reuqest to isolate computer
        isolate_url = BASE_URL + f"/computers/{computer_guid}/isolation"
        isolate_comment = {"comment": "Locked by IR Bot", "unlock_code": "unlockme"}
        status = put(isolate_url, auth=(CLIENT_ID, API_KEY), data=isolate_comment)
        response_data = json.loads(status.text)

        # Check to see if request to isolate was successful
        if response_data["data"] == {}:
            error = response_data["errors"][0]["details"]
            response.text = (
                f"Attempted to quarantine {computer}, but got an error: {error[0]}"
            )
        else:
            if response_data["data"]["status"] == "isolated":
                # If agent is online, isolation request gets processed & put in 'isolated' state
                response.text = f"Successfully quarantined {computer}."
            elif response_data["data"]["status"] == "pending_start":
                # If agent is not online, isolation request is 'pending_start'
                response.text = (
                    f"Successfully processed request to quarantine {computer}."
                )
            else:
                response.text(response_data)
        return response
