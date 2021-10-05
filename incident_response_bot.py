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

import logging
import os
from time import sleep

from webex_bot.webex_bot import WebexBot

from commands.actions import ContainmentActions
from commands.amp4e import AmpEvents
from commands.help import Help
from commands.ip_reputation import IPReputation
from commands.umbrella import UmbrellaEvents, UmbrellaInvestigate

log = logging.getLogger(__name__)

# Create new Webex bot, using access token from environmnet variable
try:
    webex_token = os.environ["WEBEX_TEAMS_ACCESS_TOKEN"]
except KeyError:
    log.error("Please ensure environmental variables exist: ")
    log.error("WEBEX_TEAMS_ACCESS_TOKEN")

# Try to load list of users/domains to restrict access
domain = os.getenv("WEBEX_RESTRICT_DOMAIN")
user = os.getenv("WEBEX_RESTRICT_USER")

# Add bot restrictions, if they were provided
if domain and user:
    bot = WebexBot(
        teams_bot_token=webex_token,
        approved_domains=[domain],
        approved_users=[user],
    )
elif domain and not user:
    bot = WebexBot(
        teams_bot_token=webex_token,
        approved_domains=[domain],
    )    
elif user and not domain:
    bot = WebexBot(
        teams_bot_token=webex_token,
        approved_users=[user],
    )
else:
    bot = WebexBot(
        teams_bot_token=webex_token,
    )

# Register comamnds with bot
# OPTIONAL: Comment out or remove any of these lines to remove bot actions
bot.add_command(AmpEvents())
bot.add_command(UmbrellaEvents())
bot.add_command(UmbrellaInvestigate())
bot.add_command(ContainmentActions())
bot.add_command(IPReputation())

# Override webex_bot module's built-in help command
# bot.help_command is used any time bot receives a command that it doesn't recognize
bot.help_command = Help()
bot.help_command.commands = bot.commands
# Using add_command(help) also handles when user directly sends "help" command to bot
help = Help()
help.commands = bot.commands
bot.add_command(help)

# Start bot listening for inbound chat messages!
bot.run()
