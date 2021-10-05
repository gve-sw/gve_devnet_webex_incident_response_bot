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

from webex_bot.models.command import Command
from webex_bot.models.response import Response

log = logging.getLogger(__name__)


class Help(Command):
    def __init__(self):
        self.commands = None
        super().__init__(
            command_keyword="help",
            help_message="Returns a short summary of available commands & descriptions.",
            card=None,
        )
        log.info("Added command: 'help'")

    def execute(self, message, attachment_actions):
        """
        Bot help function. This command does not require any input/values from the user.
        This function also executes if the bot receives a message that doesn't match
        any known/registed commands.

        Parameters:
        message - Incoming webex message, with command already stripped
        attachment - Incoming attachement / action submissions from adaptive card

        Returns:
        response - Returns list of all registed chat commands with their help text
        """
        response = (
            "Hello there! Here is a list of supported operations I can perform:\n"
        )
        # Sort list of bot commands
        sorted_commands_list = sorted(
            self.commands, key=lambda command: command.command_keyword
        )
        # Build bulleted list of available bot commands with help text
        # Format: command_keyword <input value> - Help message
        for command in sorted_commands_list:
            # Skip returning info on built-in echo / help commands
            if command.command_keyword == "echo":
                continue
            if command.command_keyword == "help":
                continue
            response += (
                f"- **{command.command_keyword}** *value* - {command.help_message}\n"
            )

        return response
