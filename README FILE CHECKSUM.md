# SHA-256
MALWARE FINDINGS 
title: Filechecksum PowerShell Download
id: 9a50b5bd-5a60-4790-985d-42e26d317f86
status: test
description: Intgrity check of Filechecksum in PowerShell command
tags:
    - Initial Access
    - attack.sha-256
author: Harinishree
date: 2017/03/05
logsource:
    product: windows
    service: powershell
detection:
    Get-FileHash|returns: False
    download:
        - '.DownloadFile('
    condition: selection
falsepositives:
    - Files that download content from the Internet
level: medium
