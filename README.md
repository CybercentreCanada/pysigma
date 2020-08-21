# Sigma Signature Library
The Sigma Signature Library works by parsing Sigma rules in a Python environment in order to evaluate Sysmon event logs and report any matches (or hits) for the logs. 

For more info on Sigma visit https://github.com/Neo23x0/sigma.

## How does it work?
The library handles the signature syntax of Sigma using Lark, which is a modern parsing library for Python. Lark is able to parse any context-free grammar and returns an output using automatic tree construction. In the context of the library, Lark is used to evaluate the condition strings within the Sigma rules and return true or false for the given Sysmon event log. 

For more info on Lark, visit https://lark-parser.readthedocs.io/en/latest/.

## Example
Example Rule:
```yaml
title: WMI Event Subscription
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: experimental
description: Detects creation of WMI event subscription persistence method
references:
    - https://attack.mitre.org/techniques/T1084/
tags:
    - attack.t1084
    - attack.persistence
    - attack.t1546.003
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
logsource:
    product: windows
    service: sysmon
detection:
    selector:
        EventID:
            - 19
            - 20
            - 21
    condition: selector
falsepositives:
    - exclude legitimate (vetted) use of WMI event subscription in your network
level: high
```
Example Output:
```
Enter event logs to test: test_a.xml

Alerts
Event: test_a.xml
[{'Abusing Azure Browser SSO': 'high'}]
```
The program takes in event logs as .xml files in a comma-separated list, and outputs a list for each event of any rules that were 'hit' and their corresponding alert levels (i.e. low, medium, high, critical).

## Work in Progress
* Handle multiple event logs within a single .xml file
* Handle complete set of Value Modifiers under syntax specifications for Sigma rules
* Handle Aggregation Expressions under syntax specifications for Sigma rules
 
## Credits
 Special thanks to the creators of Sigma and all of its contributors, starting with:
 - [Thomas Patzke](https://github.com/thomaspatzke)
 - [Florian Roth](https://github.com/Neo23x0)
 
 Another special thanks to the creator of Lark and all of its contributors, starting with:
 - [Erez Shinan](https://github.com/erezsh)
