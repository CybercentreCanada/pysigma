PRODUCT_CATEGORY_MAPPING = {
    "antivirus": {
        "antivirus": {
            "categoryDeviceGroup": "/IDS/Host/AntiVirus"
        }
    },
    "apache": {
        "apache": {
            "categoryDeviceGroup": "/Application",
            "deviceProduct": "Apache"
        },
        "apache2": {}
    },
    "azure": {
        "azure": {
            "metdata_vendor": "Microsoft"
        }
    },
    "azuread": {
        "azuread": {
            "metdata_vendor": "Microsoft"
        }
    },
    "cisco": {
        "cisco": {}
    },
    "django": {
        "application-django": {},
        "django": {
            "vendor_name": "Django"
        }
    },
    "dns": {
        "network-dns2": {}
    },
    "firewall": {
        "firewall": {
            "categoryDeviceGroup": "/Firewall"
        },
        "firewall-product": {},
        "firewall2": {}
    },
    "flow": {
        "flow": {}
    },
    "gsuite": {
        "microsoft": {}
    },
    "ipfix": {
        "ipfix": {}
    },
    "linux": {
        "linux": {
            "deviceVendor": "Unix"
        },
        "linux-auth": {},
        "linux-clamav": {
            "deviceVendor": "Unix"
        },
        "linux-sshd": {
            "deviceVendor": "Unix"
        },
        "linux-syslog": {},
        "linux-vsftpd": {
            "deviceVendor": "Unix"
        },
        "linux_auditd": {
            "event.module": "auditd"
        },
        "network_connectio_linux": {
            "EventID": 3
        },
        "process_creation_linux": {
            "EventID": 1
        }
    },
    "m365": {
        "AccessGovernance": {
            "eventSource": "SecurityComplianceCenter"
        },
        "CloudDiscovery": {
            "eventSource": "SecurityComplianceCenter"
        },
        "DataLossPrevention": {
            "eventSource": "SecurityComplianceCenter"
        },
        "SharingControl": {
            "eventSource": "SecurityComplianceCenter"
        },
        "ThreatDetection": {
            "eventSource": "SecurityComplianceCenter"
        },
        "ThreatManagement": {
            "eventSource": "SecurityComplianceCenter"
        }
    },
    "netflow": {
        "netflow": {}
    },
    "nginx": {
        "nginx": {}
    },
    "python": {
        "application-python": {},
        "python": {
            "categoryDeviceGroup": "/Application",
            "deviceProduct": "Python"
        }
    },
    "qflow": {
        "qflow": {}
    },
    "rails": {
        "application-rails": {}
    },
    "rpc_firewall": {
        "windows-rpc-firewall": {
            "source": "WinEventLog:RPCFW"
        }
    },
    "ruby_on_rails": {
        "ruby_on_rails": {
            "categoryDeviceGroup": "/Application",
            "deviceProduct": "Ruby on Rails"
        }
    },
    "spring": {
        "application-spring": {},
        "spring": {
            "categoryDeviceGroup": "/Application",
            "deviceProduct": "Spring"
        }
    },
    "sql": {
        "application-sql": {}
    },
    "unix": {
        "unix": {}
    },
    "vpn": {
        "vpn": {}
    },
    "windows": {
        "clipboard_capture": {
            "EventID": 24
        },
        "create_remote_thread": {
            "EventID": 8
        },
        "create_stream_hash": {
            "EventID": 15
        },
        "dns_query": {
            "EventID": 22
        },
        "driver_loaded": {
            "EventID": 6
        },
        "eventlogs": {
            "logSourceTypeName": "MS Windows Event Logging XML - Security"
        },
        "file_change": {
            "EventID": 2
        },
        "file_creation": {
            "EventID": 11
        },
        "file_delete": {
            "EventID": [
                23,
                26
            ]
        },
        "image_loaded": {
            "EventID": 7
        },
        "microsoft-servicebus-client": {
            "Channel": "Microsoft-ServiceBus-Client"
        },
        "network_connection": {
            "EventID": 3
        },
        "pipe_created": {
            "EventID": [
                17,
                18
            ]
        },
        "pipe_created1": {
            "EventID": 17
        },
        "pipe_created2": {
            "EventID": 18
        },
        "process_access": {
            "EventID": 10
        },
        "process_creation": {
            "EventID": 1
        },
        "process_creation_1": {},
        "process_creation_2": {
            "EventID": 4688
        },
        "process_tampering": {
            "EventID": 25
        },
        "process_terminated": {
            "EventID": 5
        },
        "ps_classic_provider_start": {
            "EventID": 600
        },
        "ps_classic_script": {
            "EventID": 800
        },
        "ps_classic_start": {
            "EventID": 400
        },
        "ps_module": {
            "EventID": 4103
        },
        "ps_script": {
            "EventID": 4104
        },
        "raw_access_thread": {
            "EventID": 9
        },
        "registry_event": {
            "EventID": [
                12,
                13,
                14
            ]
        },
        "registry_event1": {
            "EventID": 12
        },
        "registry_event2": {
            "EventID": 13
        },
        "registry_event3": {
            "EventID": 14
        },
        "sysmon_error": {
            "EventID": 255
        },
        "sysmon_status": {
            "EventID": [
                4,
                16
            ]
        },
        "sysmon_status1": {
            "EventID": 4
        },
        "sysmon_status2": {
            "EventID": 16
        },
        "windows": {},
        "windows-app": {
            "deviceVendor": "Microsoft"
        },
        "windows-application": {
            "Channel": "Application"
        },
        "windows-applocker": {
            "Channel": [
                "Microsoft-Windows-AppLocker/MSI and Script",
                "Microsoft-Windows-AppLocker/EXE and DLL",
                "Microsoft-Windows-AppLocker/Packaged app-Deployment",
                "Microsoft-Windows-AppLocker/Packaged app-Execution"
            ]
        },
        "windows-category-create_remote_thread": {},
        "windows-category-create_stream_hash": {},
        "windows-category-dns_query": {},
        "windows-category-driver_load": {},
        "windows-category-file_delete": {},
        "windows-category-file_event": {},
        "windows-category-image_load": {},
        "windows-category-network_connection": {},
        "windows-category-pipe_created": {},
        "windows-category-process_access": {},
        "windows-category-process_creation": {},
        "windows-category-raw_access_thread": {},
        "windows-category-registry_event": {},
        "windows-category-wmi_event": {},
        "windows-classicpowershell": {
            "Channel": "Windows PowerShell"
        },
        "windows-codeintegrity-operational": {
            "log_name": "Microsoft-Windows-CodeIntegrity/Operational"
        },
        "windows-create-remote-thread": {
            "product_name": "Sysmon",
            "vendor_id": "8"
        },
        "windows-defender": {
            "Channel": "Microsoft-Windows-Windows Defender/Operational"
        },
        "windows-dhcp": {
            "Channel": "Microsoft-Windows-DHCP-Server/Operational"
        },
        "windows-dns": {
            "deviceProduct": "DNS-Server",
            "deviceVendor": "Microsoft"
        },
        "windows-dns-query": {
            "product_name": "Sysmon",
            "vendor_id": "22"
        },
        "windows-dns-server": {
            "Channel": "DNS Server"
        },
        "windows-dns-server-audit": {
            "LogName": "Microsoft-Windows-DNS-Server/Audit"
        },
        "windows-driver": {
            "deviceVendor": "Microsoft"
        },
        "windows-driver-framework": {
            "Channel": "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
        },
        "windows-driver-load": {
            "product_name": "Sysmon",
            "vendor_id": "6"
        },
        "windows-file-create": {
            "product_name": "Sysmon",
            "vendor_id": "11"
        },
        "windows-file-creation": {},
        "windows-file-delete": {
            "product_name": "Sysmon",
            "vendor_id": "23"
        },
        "windows-file-event": {
            "product_name": "Sysmon",
            "vendor_id": "11"
        },
        "windows-image-load": {
            "product_name": "Sysmon",
            "vendor_id": "7"
        },
        "windows-ladp-client-debug": {
            "Channel": "Microsoft-Windows-LDAP-Client/Debug"
        },
        "windows-ldap-query": {
            "channel": "Microsoft-Windows-LDAP-Client/Debug ETW"
        },
        "windows-msexchange-management": {
            "Channel": "MSExchange Management"
        },
        "windows-network-connection": {
            "product_name": "Sysmon",
            "vendor_id": "3"
        },
        "windows-ntlm": {
            "Channel": "Microsoft-Windows-NTLM/Operational"
        },
        "windows-pc": {
            "deviceVendor": "Microsoft"
        },
        "windows-pipe-created": {
            "product_name": "Sysmon",
            "vendor_id": [
                17,
                18
            ]
        },
        "windows-power": {
            "deviceVendor": "Microsoft"
        },
        "windows-powershell": {
            "Channel": "Microsoft-Windows-PowerShell/Operational"
        },
        "windows-powershell-classic": {},
        "windows-printservice-admin": {
            "Channel": "Microsoft-Windows-PrintService/Admin"
        },
        "windows-printservice-operational": {
            "Channel": "Microsoft-Windows-PrintService/Operational"
        },
        "windows-process-access": {
            "product_name": "Sysmon",
            "vendor_id": "10"
        },
        "windows-process-creation": {},
        "windows-ps-classic-provider": {
            "product_name": "Windows PowerShell",
            "vendor_id": 600
        },
        "windows-ps-classic-script": {
            "product_name": "Windows PowerShell",
            "vendor_id": 800
        },
        "windows-ps-module": {
            "product_name": "PowerShell",
            "vendor_id": 4103
        },
        "windows-ps-script": {
            "product_name": "PowerShell",
            "vendor_id": 4104
        },
        "windows-raw-access-thread": {
            "product_name": "Sysmon",
            "vendor_id": 9
        },
        "windows-registry": {
            "vendor_id": [
                12,
                13,
                14
            ]
        },
        "windows-sec": {
            "deviceProduct": "Microsoft Windows",
            "deviceVendor": "Microsoft"
        },
        "windows-security": {
            "Channel": "Security"
        },
        "windows-service-applocker": {},
        "windows-service-dns-server": {},
        "windows-service-driver-framework": {},
        "windows-service-ntlm": {},
        "windows-service-powershell": {},
        "windows-service-powershell-classic": {},
        "windows-service-security": {},
        "windows-service-sysmon": {},
        "windows-service-system": {},
        "windows-service-taskscheduler": {},
        "windows-service-windef": {},
        "windows-service-windefend": {},
        "windows-service-wmi": {},
        "windows-servicebus-client": {
            "Channel": "Microsoft-ServiceBus-Client"
        },
        "windows-smbclient-security": {
            "Channel": "Microsoft-Windows-SmbClient/Security"
        },
        "windows-stream-hash": {
            "product_name": "Sysmon",
            "vendor_id": "15"
        },
        "windows-sys": {
            "deviceProduct": "Sysmon",
            "deviceVendor": "Microsoft"
        },
        "windows-sysmon": {
            "Channel": "Microsoft-Windows-Sysmon/Operational"
        },
        "windows-sysmon-error": {
            "product_name": "Sysmon",
            "vendor_id": "255"
        },
        "windows-sysmon-status": {
            "product_name": "Sysmon",
            "vendor_id": [
                4,
                5
            ]
        },
        "windows-system": {
            "Channel": "System"
        },
        "windows-taskscheduler": {
            "LogName": "Microsoft-Windows-TaskScheduler/Operational"
        },
        "windows-taskscheduler-operational": {
            "Channel": "Microsoft-Windows-TaskScheduler/Operational"
        },
        "windows-wmi": {
            "deviceVendor": "Microsoft"
        },
        "windows-wmi-activity-Operational": {
            "Channel": "Microsoft-Windows-WMI-Activity/Operational"
        },
        "windows-wmi-sysmon": {
            "product_name": "Sysmon",
            "vendor_id": [
                19,
                20,
                21
            ]
        },
        "wmi_event": {
            "EventID": [
                19,
                20,
                21
            ]
        },
        "wmi_event1": {
            "EventID": 19
        },
        "wmi_event2": {
            "EventID": 20
        },
        "wmi_event3": {
            "EventID": 21
        }
    },
    "windows_defender": {
        "windows-defender": {
            "deviceVendor": "Microsoft"
        },
        "windows_defender": {}
    },
    "zeek": {
        "zeek": {},
        "zeek-conn": {
            "@stream": "conn"
        },
        "zeek-conn_long": {
            "@stream": "conn_long"
        },
        "zeek-dce_rpc": {
            "@stream": "dce_rpc"
        },
        "zeek-dnp3": {
            "@stream": "dnp3"
        },
        "zeek-dns": {
            "@stream": "dns"
        },
        "zeek-dpd": {
            "@stream": "dpd"
        },
        "zeek-files": {
            "@stream": "files"
        },
        "zeek-ftp": {
            "@stream": "ftp"
        },
        "zeek-gquic": {
            "@stream": "gquic"
        },
        "zeek-http": {
            "@stream": "http"
        },
        "zeek-http2": {
            "@stream": "http2"
        },
        "zeek-intel": {
            "@stream": "intel"
        },
        "zeek-ip_search": {
            "@stream": [
                "conn",
                "conn_long",
                "dce_rpc",
                "dhcp",
                "dnp3",
                "dns",
                "ftp",
                "gquic",
                "http",
                "irc",
                "kerberos",
                "modbus",
                "mqtt_connect",
                "mqtt_publish",
                "mqtt_subscribe",
                "mysql",
                "ntlm",
                "ntp",
                "radius",
                "rfb",
                "sip",
                "smb_files",
                "smb_mapping",
                "smtp",
                "smtp_links",
                "snmp",
                "socks",
                "ssh",
                "tls",
                "tunnel",
                "weird"
            ]
        },
        "zeek-irc": {
            "@stream": "irc"
        },
        "zeek-kerberos": {
            "@stream": "kerberos"
        },
        "zeek-known_certs": {
            "@stream": "known_certs"
        },
        "zeek-known_hosts": {
            "@stream": "known_hosts"
        },
        "zeek-known_modbus": {
            "@stream": "known_modbus"
        },
        "zeek-known_services": {
            "@stream": "known_services"
        },
        "zeek-modbus": {
            "@stream": "modbus"
        },
        "zeek-modbus_register_change": {
            "@stream": "modbus_register_change"
        },
        "zeek-mqtt_connect": {
            "@stream": "mqtt_connect"
        },
        "zeek-mqtt_publish": {
            "@stream": "mqtt_publish"
        },
        "zeek-mqtt_subscribe": {
            "@stream": "mqtt_subscribe"
        },
        "zeek-mysql": {
            "@stream": "mysql"
        },
        "zeek-notice": {
            "@stream": "notice"
        },
        "zeek-ntlm": {
            "@stream": "ntlm"
        },
        "zeek-ntp": {
            "@stream": "ntp"
        },
        "zeek-ocsp": {
            "@stream": "ocsp"
        },
        "zeek-pe": {
            "@stream": "pe"
        },
        "zeek-pop3": {
            "@stream": "pop3"
        },
        "zeek-radius": {
            "@stream": "radius"
        },
        "zeek-rdp": {
            "@stream": "rdp"
        },
        "zeek-rfb": {
            "@stream": "rfb"
        },
        "zeek-sip": {
            "@stream": "sip"
        },
        "zeek-smb_files": {
            "@stream": "smb_files"
        },
        "zeek-smb_mapping": {
            "@stream": "smb_mapping"
        },
        "zeek-smtp": {
            "@stream": "smtp"
        },
        "zeek-smtp_links": {
            "@stream": "smtp_links"
        },
        "zeek-snmp": {
            "@stream": "snmp"
        },
        "zeek-socks": {
            "@stream": "socks"
        },
        "zeek-software": {
            "@stream": "software"
        },
        "zeek-ssh": {
            "@stream": "ssh"
        },
        "zeek-ssl": {
            "@stream": "ssl"
        },
        "zeek-syslog": {
            "@stream": "syslog"
        },
        "zeek-tls": {
            "@stream": "ssl"
        },
        "zeek-traceroute": {
            "@stream": "traceroute"
        },
        "zeek-tunnel": {
            "@stream": "tunnel"
        },
        "zeek-weird": {
            "@stream": "weird"
        },
        "zeek-x509": {
            "@stream": "x509"
        }
    }
}