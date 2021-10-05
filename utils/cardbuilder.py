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

import asyncio
import json
import logging
import os
from base64 import b64encode
from datetime import datetime
from types import ClassMethodDescriptorType
from urllib.parse import quote

from adaptivecardbuilder import *

log = logging.getLogger(__name__)

"""
Helper utility to build Webex AdaptiveCards.
Each funtion generates a fully assembled Webex attachment object,
containing appropriate headers & JSON payload to display AdaptiveCard. 
"""


def buildAMPEventsCard(events):
    """
    Generate Adaptive Card for Webex that contains AMP Event info

    Parameters:
    events - JSON object of AMP event data, pulled directly from AMP API

    Returns:
    card - AdaptiveCard containing list of AMP events. Primary card contains
           list of top 5 events and shows event type & user/PC info.
           Sub-cards available for top 5 events with additonal details &
           links to AMP file trajectory / computer event log.
    """
    AMP_TRACJECTORY_URL = "https://console.amp.cisco.com/file/trajectory/"
    AMP_EVENTS_URL = "https://console.amp.cisco.com/dashboard/events#/events/show/"
    log.info("Building AMP Events card...")
    card = AdaptiveCard()

    # Count how many events we run through
    counter = 1
    eventcount = len(events)

    # Card header
    card.add(
        TextBlock(f"{eventcount} AMP Events Found", size="medium", weight="bolder")
    )

    # Build primary card
    for event in events:
        # Build AMP Console URLs for events & file trajectory
        sha256 = event["file"]["identity"]["sha256"]
        tracjectory_url = AMP_TRACJECTORY_URL + sha256
        event_filter = {
            "filters": {
                "ag": [event["connector_guid"]],
                "time": ["week"],
                "sha": [sha256],
            },
            "sort_by": "ts",
            "sort_order": "desc",
        }
        events_url = AMP_EVENTS_URL + str(event_filter)
        if counter == 6:
            # Currently AdaptiveCards only show up to 5 actions/sub-cards.
            # So after 5 are generated, add text to show how many additional events were returned
            card.add(TextBlock(f"And {eventcount - 5} additional events."))
            break
        # Build sub-card with additional event details & links to AMP console
        try:
            card.add(
                TextBlock(
                    f"#{counter}: {event['event_type']} on {event['computer']['hostname']} "
                    + f"(User: {(event['computer']['user']).split('@')[0]})"
                )
            )
        except KeyError:
            # Some AMP Events may not contain a user field
            card.add(
                TextBlock(
                    f"#{counter}: {event['event_type']} on {event['computer']['hostname']} "
                )
            )

        # Build sub-cards for top 5 events, with links to AMP console
        card.add(
            [
                ActionShowCard(title=f"Details (#{counter})"),
                ColumnSet(),
                Column(style="emphasis"),
                TextBlock(f"Computer: {event['computer']['hostname']}"),
                TextBlock(
                    f"Detected at: {(event['date']).split('T')[0]} {(event['date']).split('T')[1][:5]}"
                ),
                TextBlock(f"Threat: {event['detection']}"),
                TextBlock(f"File Name: {event['file']['file_name']}"),
                TextBlock(f"Source IP: {event['computer']['external_ip']}"),
                ActionSet(),
                ActionOpenUrl(title="File Trajectory", url=tracjectory_url),
                ActionOpenUrl(title="Computer Events", url=events_url),
                "^",
            ]
        )
        counter += 1
    # Add Webex attachment headers for cards
    card = generateCardPayload(card)
    log.info("Card Generated.")

    return card


def sendContainmentActions(computer):
    """
    Generate AdaptiveCard of possible containment actions against compromised computer.
    Current supported actions include sending email notification to user or
    calling AMP API to request isolation of a computer

    Parameters:
    computer - Hostname of target PC to take actions against

    Returns:
    card - AdaptiveCard containing list of possible actions to take, including
           short description of each action & input/submission ability
    """
    log.info("Building containment actions card...")
    card = AdaptiveCard()
    # Build card
    card.add(
        [
            TextBlock(text="Containment Actions", size="medium", weight="bolder"),
            FactSet(),
            Fact(title="Target system:", value=f"{computer}"),
            "^",
            TextBlock("Available Options:"),
            TextBlock("- Quarantine: Isolate computer from network"),
            TextBlock("- Notify User: Email user to bring in laptop for inspection"),
            TextBlock("Please select an action below:"),
            # Action buttons will contain custom data fields:
            # callback_keyword - which bot command to send response to
            # requested_action - value to identify what action user chose to take
            # target_compter - hostname of target PC, so we can keep track of what PC we are dealing with
            ActionSubmit(
                title="Quarantine",
                ID="quarantine",
                data={
                    "callback_keyword": "actions",
                    "requested_action": "quarantine",
                    "target_computer": computer,
                },
            ),
            ActionShowCard(title="Notify User"),
            InputText(ID="user_email_addr", placeholder="Enter email address"),
            ActionSubmit(
                title="Send Message",
                ID="notify",
                data={
                    "callback_keyword": "actions",
                    "requested_action": "notify user",
                    "target_computer": computer,
                },
            ),
        ]
    )
    # Add Webex attachment headers for cards
    card = generateCardPayload(card)
    log.info("Card Generated.")

    return card


def buildUmbrellaEventsCard(org_id, events):
    """
    Generate Adaptive Card for Webex that contains Umbrella security event info

    Parameters:
    org_id - Umbrella Organization ID. Required to build URL to link directly to reporting dashboard
    events - JSON object of Umbrella events, pulled directly from Umbrella reporting API

    Returns:
    card - AdaptiveCard containing list of Umbrella events. Primary card contains
           list of top 5 events and shows URL.
           Sub-cards available for top 5 events with additonal details &
           links to Umbrella event log.
    """
    log.info("Building Umbrella Events card...")
    # Base URL for Umbrella reporting, to be used for card links
    reporting_url = (
        f"https://dashboard.umbrella.com/o/{org_id}/#/reports/activity?encodedFilters="
    )

    # Count how many events we run through
    counter = 1
    eventcount = len(events["data"])
    card = AdaptiveCard()

    # Card header
    card.add(
        TextBlock(f"{eventcount} Umbrella Events Found", size="medium", weight="bolder")
    )
    # Add event info
    for event in events["data"]:
        # Assemble reporting URL parameters for links:
        reporting_filters = f'{{"selectedDateRangeIdx":3,"domain":[{{"id":"{event["domain"]}","label":"{event["domain"]}"}}]}}'
        # Dashboard URLs use query parameters that are escaped then b64 encoded
        url_params = quote(
            b64encode(quote(str(reporting_filters)).encode("ascii")).decode("utf-8")
        )
        full_url = reporting_url + str(url_params)
        if counter == 6:
            # Currently AdaptiveCards only show up to 5 actions/sub-cards.
            # So after 5 are generated, add text to show how many additional events were returned
            card.add(TextBlock(f"And {eventcount - 5} additional events."))
            break
        # Build sub-card containing additional event info
        card.add(
            [
                TextBlock(f"#{counter}: {event['domain']}"),
                ActionShowCard(title=f"Details (#{counter})"),
                ColumnSet(),
                Column(style="emphasis"),
                TextBlock(f"Detected at: {event['date']} {event['time']}"),
                TextBlock(f"Source IP: {event['externalip']}"),
                TextBlock(f"Action: {event['verdict']}"),
                "<",
                "<",
                ActionOpenUrl(title="Open Event Log", url=full_url),
                "^",
            ]
        )
        counter += 1

    # Add Webex attachment headers for cards
    card = generateCardPayload(card)
    log.info("Card Generated.")

    return card


def buildUmbrellaInvestigateCard(domain_data):
    """
    Generate Adaptive Card for Webex that contains Umbrella investigate data

    Parameters:
    domain_data - Incoming dictionary of Umbrella investigate values

    Returns:
    card - AdaptiveCard containing detailed info about a single domain name
    """
    log.info("Building Umbrella investigate card")

    card = AdaptiveCard()
    # Take list of content/security categories and join to create text for card
    if len(domain_data["security_categories"]) == 0:
        security_categories = "None"
    else:
        security_categories = ", ".join(domain_data["security_categories"])
    if len(domain_data["content_categories"]) == 0:
        content_categories = "None"
    else:
        content_categories = ", ".join(domain_data["content_categories"])

    # Build card with Umbrella investigate info
    card.add(
        [
            TextBlock("Umbrella Investigate Data", size="medium", weight="bolder"),
            FactSet(),
            Fact(title="Domain name:", value=f"{domain_data['url']}"),
            Fact(title="Risk Score:", value=f"{domain_data['risk_score']}"),
            Fact(title="Security Categories:", value=f"{security_categories}"),
            Fact(title="Content Categories:", value=f"{content_categories}"),
            Fact(title="Registrar:", value=f"{domain_data['registrar']}"),
            Fact(title="Registed Date:", value=f"{domain_data['created']}"),
            Fact(title="Expiration Date:", value=f"{domain_data['expires']}"),
            "^",
        ]
    )
    # Add Webex attachment headers for cards
    card = generateCardPayload(card)
    log.info("Card Generated.")

    return card


def buildIPReputationCard(ip_data):
    """
    Build Adaptive Card containing reputation data from IP address lookup

    Parameters:
    ip_data - Incoming dictionary of IP reputation info from SpamHaus

    Returns:
    card - AdaptiveCard containing formatted IP reputation info
    """
    log.info("Building IP Reputation card")
    last_seen = (datetime.fromtimestamp(ip_data[0]["seen"]).isoformat()).split("T")

    card = AdaptiveCard()
    # Build Card
    card.add(
        [
            TextBlock(
                text=f"IP Reputation for {ip_data[0]['ipaddress']}",
                size="medium",
                weight="bolder",
            ),
            ColumnSet(),
            Column(style="emphasis"),
            FactSet(),
            Fact("Detected Activity: ", ip_data[0]["detection"]),
            Fact("Determination: ", ip_data[0]["heuristic"]),
            Fact("Country: ", ip_data[0]["cc"]),
            Fact("Last Seen: ", f"{last_seen[0]} {last_seen[1]}"),
            "^",
        ]
    )
    # Add Webex attachment headers for cards
    card = generateCardPayload(card)
    log.info("Card Generated.")

    return card


def generateCardPayload(card):
    """
    Wrap AdaptiveCard JSON data in the correct headers/format for Webex attachments

    Parameters:
    card - Incoming AdaptiveCard object containing pre-built JSON card

    Returns:
    card_payload - Final AdaptiveCard object, ready to be attached to a Webex message
    """
    # Convert AdaptiveCard object to JSON
    card_data = json.loads(asyncio.run(card.to_json()))
    # Add headers
    card_payload = {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": card_data,
    }
    return card_payload
