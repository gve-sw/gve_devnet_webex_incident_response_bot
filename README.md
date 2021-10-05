# GVE DevNet - Webex Incident Response Bot

Webex bot to demonstrate ability to interact with multiple Cisco & non-Cisco products via chatbot. The purpose of this bot is to provide customer security / incident response teams quicker, centralized access to security event data. By gaining access to information more quickly, customer security teams can be more efficient in responding to threats in their network.

## Contacts
* Matt Schmitz (mattsc@cisco.com)

## Solution Components
* Webex teams
* AMP for Endpoints
* Umbrella Reporting & Investigate
* SpamHaus Intelligence API

## Installation/Configuration

**Clone repo:**
```bash
git clone <repo_url>
```

**Install required dependancies:**
```bash
pip install -r requirements.txt
```

**Configure Required environmental variables:**
```bash
#!/bin/bash

# Webex access token - Required for bot operation 
export WEBEX_TEAMS_ACCESS_TOKEN=""

# Optional: limit bot access by domain name or individual user (by email address)
export WEBEX_RESTRICT_DOMAIN="cisco.com"
export WEBEX_RESTRICT_USER="mattsc@cisco.com"

# Umbrella API Keys - Required for ability to query Umbrella reporting / investigate data
export UMBRELLA_CLIENT_ID=""
export UMBRELLA_API_KEY=""
export UMBRELLA_INVESTIGATE_KEY=""
export UMBRELLA_ORG_ID=""

# AMP API Keys - Required for ability to query AMP4E events, or execute computer isolation commands
# Note: For endpoint isolation, API must have write access. Computer policy must also be configured to allow isolation
export AMP4E_CLIENT_ID=""
export AMP4E_API_KEY=""

# SpamHaus API Keys - Required for abiltiy to query SpamHaus Intelligence API for IP reputation data
export SPAMHAUS_USER=""
export SPAMHAUS_PASS=""

# SMTP Relay - Required for ability to send email notifications to user with compromised system
export SMTP_RELAY=""
export SMTP_PORT=""
export SMTP_SENDER_ADDR=""
```

**Optional: Disable undesired bot functionality**

If there are any product which are not available or undesired, please edit ```incident_response_bot.py``` and comment out any of the ```bot.add_command()``` functions for the undesired actions.

Example, removing Umbrella Investigate:
```python
bot.add_command(AmpEvents())
bot.add_command(UmbrellaEvents())
# bot.add_command(UmbrellaInvestigate())
bot.add_command(ContainmentActions())
bot.add_command(IPReputation())
```

## Usage

Bot uses Webex websockets to establish a persistent connection to the Webex cloud. 

Once all environmental variables have been configured, simply run the bot & it will begin listening for incoming messages:

```
python incident_response_bot.py
```



# Screenshots

**Bot help:**

![/IMAGES/help-prompt.png](/IMAGES/help-prompt.png)

**Requesting AMP4E event data:**

![/IMAGES/amp-events.png](/IMAGES/amp-events.png)

**Requesting Umbrella security events:**

![/IMAGES/umbrella-events.png](/IMAGES/umbrella-events.png)

**Requesting Umbrella Investigate data for a single domain:**

![/IMAGES/umbrella-investigate.png](/IMAGES/umbrella-investigate.png)

**Using bot to quarantine a computer:**

![/IMAGES/actions-quarantine.png](/IMAGES/actions-quarantine.png)


### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.