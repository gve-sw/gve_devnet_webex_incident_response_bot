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
import smtplib

log = logging.getLogger(__name__)


"""
Quick helper utility to send mail via SMTP.
Please note, this only supports plain/non-TLS, unauthenticated SMTP relay.
"""

# Pre-formatted message to send user
message = """Subject: Notification from Security Team

Hello there!

It appears your computer {pc} has been infected with malware. Please bring it to the helpdesk as soon as possible for inspection.

A temporary device will be provided while yours is being examined.

Thank you,
Security
"""

try:
    smtp_server = os.environ["SMTP_RELAY"]
    port = os.environ["SMTP_PORT"]
    from_addr = os.environ["SMTP_SENDER_ADDR"]
except KeyError:
    log.error("Could not find SMTP relay config.")
    log.error("Please ensure environmental variables exist: ")
    log.error("SMTP_RELAY")
    log.error("SMTP_PORT")
    log.error("SMTP_SENDER_ADDR")


def sendMail(computer_name, to_addr):
    """
    Send mail message via SMTP relay

    Parameters:
    computer_name - User's computer hostname, to inject into email message
    to_addr - Target email address to send message to
    """
    try:
        connection = smtplib.SMTP(smtp_server, port)
        connection.sendmail(from_addr, to_addr, message.format(pc=computer_name))
    except Exception as e:
        log.error(e)
    finally:
        connection.quit()
