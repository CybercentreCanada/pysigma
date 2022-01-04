PRODUCT_CATEGORY_MAPPING = {
    "antivirus": {
        "antivirus": {
            "vendor_type": "Antivirus"
        }
    },
    "apache": {
        "apache": {
            "product_name": [
                "apache*",
                "httpd*"
            ]
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
        "cisco": {
            "vendor_name": "Cisco"
        }
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
        "linux": {},
        "linux-auth": {
            "device.class": "rhlinux"
        },
        "linux-clamav": {
            "device.class": "rhlinux"
        },
        "linux-sshd": {
            "client": "sshd",
            "device.class": "rhlinux"
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
    "ruby_on_rails": {
        "ruby_on_rails": {
            "categoryDeviceGroup": "/Application",
            "deviceProduct": "Ruby on Rails"
        }
    },
    "spring": {
        "application-spring": {},
        "spring": {
            "vendor_name": "Spring"
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
            "EventID": 4688
        },
        "process_creation_1": {
            "EventID": 1
        },
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
            "EventID": 4657,
            "OperationType": [
                "New registry value created",
                "Existing registry value modified"
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
        "windows": {
            "vendor_name": "Microsoft"
        },
        "windows-app": {
            "deviceVendor": "Microsoft"
        },
        "windows-application": {
            "product_name": "Application"
        },
        "windows-applocker": {
            "product_name": [
                "AppLocker"
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
            "product_name": "Windows PowerShell"
        },
        "windows-create-remote-thread": {
            "product_name": "Sysmon",
            "vendor_id": "8"
        },
        "windows-defender": {
            "product_name": "Windows Defender"
        },
        "windows-dhcp": {
            "product_name": "DHCP-Server"
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
            "channel": "DNS Server"
        },
        "windows-dns-server-audit": {
            "channel": "DNS Server"
        },
        "windows-driver": {
            "deviceVendor": "Microsoft"
        },
        "windows-driver-framework": {
            "product_name": "DriverFrameworks-UserMode"
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
        "windows-ldap-query": {
            "channel": "Microsoft-Windows-LDAP-Client/Debug ETW"
        },
        "windows-msexchange-management": {
            "channel": "MSExchange Management"
        },
        "windows-network-connection": {
            "product_name": "Sysmon",
            "vendor_id": "3"
        },
        "windows-ntlm": {
            "product_name": "NTLM"
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
            "device.type": "winevent_nic"
        },
        "windows-powershell": {
            "product_name": "PowerShell"
        },
        "windows-powershell-classic": {},
        "windows-printservice-admin": {
            "product_name": "PrintService"
        },
        "windows-printservice-operational": {
            "product_name": "PrintService"
        },
        "windows-process-access": {
            "product_name": "Sysmon",
            "vendor_id": "10"
        },
        "windows-process-creation": {
            "product_name": "Sysmon",
            "vendor_id": "1"
        },
        "windows-ps-module": {
            "product_name": "PowerShell",
            "vendor_id": 4103
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
            "device.type": "winevent_nic",
            "event.source": "microsoft-windows-security-auditing"
        },
        "windows-security": {
            "product_name": "Security"
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
        "windows-smbclient-security": {
            "product_name": "SmbClient"
        },
        "windows-stream-hash": {
            "product_name": "Sysmon",
            "vendor_id": "15"
        },
        "windows-sys": {
            "device.type": "winevent_nic",
            "event.source": "microsoft-windows-security-auditing"
        },
        "windows-sysmon": {
            "product_name": "Sysmon"
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
            "product_name": "System"
        },
        "windows-taskscheduler": {
            "product_name": "TaskScheduler"
        },
        "windows-wmi": {
            "product_name": "WMI-Activity"
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
        "zeek": {
            "vendor_name": "Zeek IDS"
        },
        "zeek-conn": {},
        "zeek-conn_long": {
            "sourcetype": "bro:conn_long:json"
        },
        "zeek-dce_rpc": {
            "sourcetype": "bro:dce_rpc:json"
        },
        "zeek-dnp3": {
            "sourcetype": "bro:dnp3:json"
        },
        "zeek-dns": {
            "sourcetype": "bro:dns:json"
        },
        "zeek-dpd": {
            "sourcetype": "bro:dpd:json"
        },
        "zeek-files": {
            "sourcetype": "bro:files:json"
        },
        "zeek-ftp": {
            "sourcetype": "bro:ftp:json"
        },
        "zeek-gquic": {
            "sourcetype": "bro:gquic:json"
        },
        "zeek-http": {
            "sourcetype": "bro:http:json"
        },
        "zeek-http2": {
            "sourcetype": "bro:http2:json"
        },
        "zeek-intel": {
            "sourcetype": "bro:intel:json"
        },
        "zeek-ip_search": {
            "sourcetype": [
                "bro:conn:json",
                "bro:conn_long:json",
                "bro:dce_rpc:json",
                "bro:dhcp:json",
                "bro:dnp3:json",
                "bro:dns:json",
                "bro:ftp:json",
                "bro:gquic:json",
                "bro:http:json",
                "bro:irc:json",
                "bro:kerberos:json",
                "bro:modbus:json",
                "bro:mqtt_connect:json",
                "bro:mqtt_publish:json",
                "bro:mqtt_subscribe:json",
                "bro:mysql:json",
                "bro:ntlm:json",
                "bro:ntp:json",
                "bro:radius:json",
                "bro:rfb:json",
                "bro:sip:json",
                "bro:smb_files:json",
                "bro:smb_mapping:json",
                "bro:smtp:json",
                "bro:smtp_links:json",
                "bro:snmp:json",
                "bro:socks:json",
                "bro:ssh:json",
                "bro:ssl:json",
                "bro:tunnel:json",
                "bro:weird:json"
            ]
        },
        "zeek-irc": {
            "sourcetype": "bro:irc:json"
        },
        "zeek-kerberos": {
            "sourcetype": "bro:kerberos:json"
        },
        "zeek-known_certs": {
            "sourcetype": "bro:known_certs:json"
        },
        "zeek-known_hosts": {
            "sourcetype": "bro:known_hosts:json"
        },
        "zeek-known_modbus": {
            "sourcetype": "bro:known_modbus:json"
        },
        "zeek-known_services": {
            "sourcetype": "bro:known_services:json"
        },
        "zeek-modbus": {
            "sourcetype": "bro:modbus:json"
        },
        "zeek-modbus_register_change": {
            "sourcetype": "bro:modbus_register_change:json"
        },
        "zeek-mqtt_connect": {
            "sourcetype": "bro:mqtt_connect:json"
        },
        "zeek-mqtt_publish": {
            "sourcetype": "bro:mqtt_publish:json"
        },
        "zeek-mqtt_subscribe": {
            "sourcetype": "bro:mqtt_subscribe:json"
        },
        "zeek-mysql": {
            "sourcetype": "bro:mysql:json"
        },
        "zeek-notice": {
            "sourcetype": "bro:notice:json"
        },
        "zeek-ntlm": {
            "sourcetype": "bro:ntlm:json"
        },
        "zeek-ntp": {
            "sourcetype": "bro:ntp:json"
        },
        "zeek-ocsp": {
            "sourcetype": "bro:ocsp:json"
        },
        "zeek-pe": {
            "sourcetype": "bro:pe:json"
        },
        "zeek-pop3": {
            "sourcetype": "bro:pop3:json"
        },
        "zeek-radius": {
            "sourcetype": "bro:radius:json"
        },
        "zeek-rdp": {
            "sourcetype": "bro:rdp:json"
        },
        "zeek-rfb": {
            "sourcetype": "bro:rfb:json"
        },
        "zeek-sip": {
            "sourcetype": "bro:sip:json"
        },
        "zeek-smb_files": {
            "sourcetype": "bro:smb_files:json"
        },
        "zeek-smb_mapping": {
            "sourcetype": "bro:smb_mapping:json"
        },
        "zeek-smtp": {
            "sourcetype": "bro:smtp:json"
        },
        "zeek-smtp_links": {
            "sourcetype": "bro:smtp_links:json"
        },
        "zeek-snmp": {
            "sourcetype": "bro:snmp:json"
        },
        "zeek-socks": {
            "sourcetype": "bro:socks:json"
        },
        "zeek-software": {
            "sourcetype": "bro:software:json"
        },
        "zeek-ssh": {
            "sourcetype": "bro:ssh:json"
        },
        "zeek-ssl": {
            "sourcetype": "bro:ssl:json"
        },
        "zeek-syslog": {
            "sourcetype": "bro:syslog:json"
        },
        "zeek-tls": {
            "sourcetype": "bro:ssl:json"
        },
        "zeek-traceroute": {
            "sourcetype": "bro:traceroute:json"
        },
        "zeek-tunnel": {
            "sourcetype": "bro:tunnel:json"
        },
        "zeek-weird": {
            "sourcetype": "bro:weird:json"
        },
        "zeek-x509": {
            "sourcetype": "bro:x509:json"
        }
    }
}