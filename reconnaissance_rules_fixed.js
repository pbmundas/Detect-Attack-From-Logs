const rules = [
    // T1595 - Active Scanning
    {
        id: 'T1595',
        name: 'Active Scanning',
        description: 'Adversaries may execute active reconnaissance scans to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && // Added 4103 for PowerShell module logging
                    (commandLine.includes('nmap') || commandLine.includes('scan') || commandLine.includes('masscan') || commandLine.includes('zmap') || 
                     image.includes('nmap.exe') || parentImage.includes('powershell.exe') || commandLine.includes('netscan'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443|22|3389|445/) && event.Protocol?.toLowerCase() === 'tcp') { // Added more ports (RDP, SMB) and protocol check
                    return true;
                }
                if (eid === '22' && commandLine.includes('scan')) { // Added DNS query logging for scan-related domains
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('scan');
        }
    },
    {
        id: 'T1595.001',
        name: 'Active Scanning: Scanning IP Blocks',
        description: 'Adversaries may scan IP blocks to identify active hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('nmap') || commandLine.includes('ip scan') || commandLine.includes('angry ip') || commandLine.includes('advanced ip scanner') || 
                     commandLine.includes('netdiscover') || parentImage.includes('cmd.exe'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) && event.User?.toLowerCase() !== 'system') { // Refined IP check with user context
                    return true;
                }
                if (eid === '22' && commandLine.includes('ip')) { // DNS queries related to IP scanning
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('ip scan');
        }
    },
    {
        id: 'T1595.002',
        name: 'Active Scanning: Vulnerability Scanning',
        description: 'Adversaries may scan for vulnerabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('nessus') || commandLine.includes('vulnerability scan') || commandLine.includes('openvas') || commandLine.includes('nikto') || 
                     commandLine.includes('acunetix') || commandLine.includes('burp suite') || image.includes('nessus.exe'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/tenable\.com|qualys\.com|rapid7\.com|shodan\.io/)) { // Added more vuln scanner domains
                    return true;
                }
                if (eid === '22' && commandLine.includes('vuln')) { // DNS queries for vuln-related sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('vulnerability scan');
        }
    },
    {
        id: 'T1595.003',
        name: 'Active Scanning: Wordlist Scanning',
        description: 'Adversaries may use wordlists to scan for resources.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('wordlist') || commandLine.includes('dirb') || commandLine.includes('gobuster') || commandLine.includes('wfuzz') || 
                     commandLine.includes('dirbuster') || commandLine.includes('ffuf'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/\/[a-z0-9]+/) && (event.Status?.includes('404') || event.Status?.includes('403'))) { // Added check for directory probes with error responses
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('wordlist');
        }
    },
    // T1592 - Gather Victim Host Information
    {
        id: 'T1592',
        name: 'Gather Victim Host Information',
        description: 'Adversaries may gather information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && // Added 4104 for script block logging
                    (commandLine.includes('systeminfo') || commandLine.includes('wmic') || commandLine.includes('hostname') || commandLine.includes('ver') || 
                     commandLine.includes('get-wmiobject') || image.includes('systeminfo.exe') || parentImage.includes('powershell.exe'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('system\\currentcontrolset')) { // Added registry event for host info queries
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('systeminfo');
        }
    },
    {
        id: 'T1592.001',
        name: 'Gather Victim Host Information: Hardware',
        description: 'Adversaries may gather hardware information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('wmic bios') || commandLine.includes('hardware info') || commandLine.includes('dmidecode') || commandLine.includes('lshw'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('hardwareprofile')) { // Registry access for hardware
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('hardware info');
        }
    },
    {
        id: 'T1592.002',
        name: 'Gather Victim Host Information: Software',
        description: 'Adversaries may gather software information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('wmic product') || commandLine.includes('software info') || commandLine.includes('get-wmiobject win32_product') || commandLine.includes('reg query hklm\\software'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('software\\microsoft\\windows\\currentversion\\uninstall')) { // Registry for installed software
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('software info');
        }
    },
    {
        id: 'T1592.003',
        name: 'Gather Victim Host Information: Firmware',
        description: 'Adversaries may gather firmware information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('firmware') || commandLine.includes('bios') || commandLine.includes('wmic csproduct') || commandLine.includes('uefi'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('firmware')) { // Registry for firmware
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('firmware');
        }
    },
    {
        id: 'T1592.004',
        name: 'Gather Victim Host Information: Client Configurations',
        description: 'Adversaries may gather client configuration information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('net config') || commandLine.includes('client config') || commandLine.includes('ipconfig /all') || commandLine.includes('get-netipconfiguration'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('network')) { // Registry for network configs
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('client config');
        }
    },
    // T1589 - Gather Victim Identity Information
    {
        id: 'T1589',
        name: 'Gather Victim Identity Information',
        description: 'Adversaries may gather identity information about victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName && event.FailureReason?.includes('unknown user')) { // Refined failed logons
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('credential') || commandLine.includes('whoami') || commandLine.includes('net user') || parentImage.includes('powershell.exe'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com|facebook\.com/)) { // Added social sites for identity gathering
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('credential');
        }
    },
    {
        id: 'T1589.001',
        name: 'Gather Victim Identity Information: Credentials',
        description: 'Adversaries may gather credentials of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toLowerCase().includes('admin') && event.LogonType === '3') { // Network logon failures
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('credential harvest') || commandLine.includes('mimikatz') || commandLine.includes('lsadump') || commandLine.includes('pwdump'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('credential harvest');
        }
    },
    {
        id: 'T1589.002',
        name: 'Gather Victim Identity Information: Email Addresses',
        description: 'Adversaries may gather email addresses of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('email address') || commandLine.includes('theharvester') || commandLine.includes('hunter.io'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/gmail\.com|outlook\.com|protonmail\.com/)) { // Added more email domains
                    return true;
                }
                if (eid === '22' && commandLine.match(/@[a-z]+\.[a-z]+/)) { // DNS queries with email patterns
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email address');
        }
    },
    {
        id: 'T1589.003',
        name: 'Gather Victim Identity Information: Employee Names',
        description: 'Adversaries may gather employee names of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('employee name') || commandLine.includes('linkedin scraper') || commandLine.includes('net user /domain'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com|zoominfo\.com/)) { // Added more people search sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('employee name');
        }
    },
    // T1590 - Gather Victim Network Information
    {
        id: 'T1590',
        name: 'Gather Victim Network Information',
        description: 'Adversaries may gather network information about victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('net view') || commandLine.includes('network info') || commandLine.includes('arp -a') || commandLine.includes('get-netneighbor') || 
                     parentImage.includes('cmd.exe'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Protocol?.toLowerCase() === 'udp') { // Added protocol for network discovery
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network info');
        }
    },
    {
        id: 'T1590.001',
        name: 'Gather Victim Network Information: Domain Properties',
        description: 'Adversaries may gather domain properties of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('whois') || commandLine.includes('domain info') || commandLine.includes('nslookup -type=soa'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/whois\.org|icann\.org/)) { // Added more domain info sites
                    return true;
                }
                if (eid === '22' && commandLine.includes('whois')) { // DNS queries for whois
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('whois');
        }
    },
    {
        id: 'T1590.002',
        name: 'Gather Victim Network Information: DNS',
        description: 'Adversaries may gather DNS information of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('nslookup') || commandLine.includes('dig') || commandLine.includes('host') || commandLine.includes('resolve-dnsname'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53') && event.Protocol?.toLowerCase() === 'udp') { // Refined with protocol
                    return true;
                }
                if (eid === '22' && commandLine.includes('dns')) { // DNS query logging
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dns');
        }
    },
    {
        id: 'T1590.003',
        name: 'Gather Victim Network Information: Network Trust Dependencies',
        description: 'Adversaries may gather information on network trust dependencies.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('net group') || commandLine.includes('network trust') || commandLine.includes('nltest /domain_trusts') || commandLine.includes('get-adtrust'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/\.local|\.internal/)) { // Internal domain patterns
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network trust');
        }
    },
    {
        id: 'T1590.004',
        name: 'Gather Victim Network Information: Network Topology',
        description: 'Adversaries may gather network topology information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('tracert') || commandLine.includes('traceroute') || commandLine.includes('mtr') || commandLine.includes('pathping'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) && event.Protocol?.toLowerCase() === 'icmp') { // ICMP for topology mapping
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network topology');
        }
    },
    {
        id: 'T1590.005',
        name: 'Gather Victim Network Information: IP Addresses',
        description: 'Adversaries may gather IP address information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('ipconfig') || commandLine.includes('ifconfig') || commandLine.includes('get-netipaddress') || commandLine.includes('nslookup'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
                    return true;
                }
                if (eid === '22' && commandLine.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) { // DNS reverse lookups
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('ip address');
        }
    },
    {
        id: 'T1590.006',
        name: 'Gather Victim Network Information: Network Security Appliances',
        description: 'Adversaries may gather information on network security appliances.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('firewall info') || commandLine.includes('netsh advfirewall') || commandLine.includes('ufw status') || commandLine.includes('iptables -L'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/paloaltonetworks\.com|cisco\.com|fortinet\.com|checkpoint\.com/)) { // Added more appliance vendors
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('firewall info');
        }
    },
    // T1591 - Gather Victim Org Information
    {
        id: 'T1591',
        name: 'Gather Victim Org Information',
        description: 'Adversaries may gather organizational information about victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('org info') || commandLine.includes('crunchbase') || commandLine.includes('net group /domain'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com|company\.com|crunchbase\.com/)) { // Added org info sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('org info');
        }
    },
    {
        id: 'T1591.001',
        name: 'Gather Victim Org Information: Determine Physical Locations',
        description: 'Adversaries may gather physical location information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('location info') || commandLine.includes('geocode') || commandLine.includes('ip geolocation'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/maps\.google\.com|ipinfo\.io|maxmind\.com/)) { // Added geo services
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('location info');
        }
    },
    {
        id: 'T1591.002',
        name: 'Gather Victim Org Information: Business Relationships',
        description: 'Adversaries may gather information on business relationships.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('business relationship') || commandLine.includes('partner info') || commandLine.includes('supply chain'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com|bloomberg\.com/)) { // Added business info sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('business relationship');
        }
    },
    {
        id: 'T1591.003',
        name: 'Gather Victim Org Information: Identify Business Tempo',
        description: 'Adversaries may identify business tempo of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('business tempo') || commandLine.includes('operation hours') || commandLine.includes('activity pattern'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/company\.com|glassdoor\.com/)) { // Added review sites for tempo info
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('business tempo');
        }
    },
    {
        id: 'T1591.004',
        name: 'Gather Victim Org Information: Identify Roles',
        description: 'Adversaries may identify roles within victim organizations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('org roles') || commandLine.includes('executive team') || commandLine.includes('directory search'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com|rocketreach\.co/)) { // Added role search sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('org roles');
        }
    },
    // T1598 - Phishing for Information
    {
        id: 'T1598',
        name: 'Phishing for Information',
        description: 'Adversaries may use phishing to gather sensitive information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('phishing') || commandLine.includes('credential prompt') || commandLine.includes('evilginx') || parentImage.includes('outlook.exe'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.pdf|\.xls|\.rtf/) && event.Creator?.toLowerCase().includes('unknown')) { // Suspicious file creation
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/phish\.site|evil\.com/)) { // Phishing domains
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('phishing');
        }
    },
    {
        id: 'T1598.001',
        name: 'Phishing for Information: Spearphishing Service',
        description: 'Adversaries may use spearphishing services to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('spearphishing service') || commandLine.includes('gophish') || commandLine.includes('king phisher'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/phish\.site|gophish\.org/)) { // Added phishing tool sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('spearphishing service');
        }
    },
    {
        id: 'T1598.002',
        name: 'Phishing for Information: Spearphishing Attachment',
        description: 'Adversaries may use spearphishing attachments to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('spearphishing attachment') || commandLine.includes('malicious doc') || commandLine.includes('outlook /safe'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.pdf|\.xls|\.exe|\.zip/) && event.Image?.includes('winword.exe')) { // Office apps creating suspicious files
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('spearphishing attachment');
        }
    },
    {
        id: 'T1598.003',
        name: 'Phishing for Information: Spearphishing Link',
        description: 'Adversaries may use spearphishing links to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('spearphishing link') || commandLine.includes('bit.ly') || commandLine.includes('tinyurl'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Referer?.includes('mail')) { // Links from email referers
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('spearphishing link');
        }
    },
    {
        id: 'T1598.004',
        name: 'Phishing for Information: Spearphishing Voice',
        description: 'Adversaries may use voice-based spearphishing to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('voice phishing') || commandLine.includes('vishing') || commandLine.includes('deepfake audio'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/5060|5061/) ) { // SIP ports for VoIP
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('voice phishing');
        }
    },
    // T1596 - Search Victim-Owned Websites
    {
        id: 'T1596',
        name: 'Search Victim-Owned Websites',
        description: 'Adversaries may search victim-owned websites for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('website search') || commandLine.includes('wget') || commandLine.includes('curl') || commandLine.includes('site scrape'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.UserAgent?.includes('bot')) { // Bot-like user agents
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('website search');
        }
    },
    {
        id: 'T1596.001',
        name: 'Search Victim-Owned Websites: DNS/Passive DNS',
        description: 'Adversaries may search DNS records of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('passive dns') || commandLine.includes('dns lookup') || commandLine.includes('virustotal dns') || commandLine.includes('robtex'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true;
                }
                if (eid === '22' && commandLine.includes('passive')) { // DNS query for passive tools
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('passive dns');
        }
    },
    {
        id: 'T1596.002',
        name: 'Search Victim-Owned Websites: WHOIS',
        description: 'Adversaries may search WHOIS records of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('whois') || commandLine.includes('domaintools') || commandLine.includes('whoisxmlapi'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/whois\.org|domaintools\.com/)) { // Added whois services
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('whois');
        }
    },
    {
        id: 'T1596.003',
        name: 'Search Victim-Owned Websites: Digital Certificates',
        description: 'Adversaries may search digital certificates of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('certificate info') || commandLine.includes('openssl s_client') || commandLine.includes('sslyze') || commandLine.includes('crt.sh'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/digicert\.com|letsencrypt\.org|crt\.sh/)) { // Added cert search sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('certificate info');
        }
    },
    {
        id: 'T1596.004',
        name: 'Search Victim-Owned Websites: CDN',
        description: 'Adversaries may search CDN information of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('cdn info') || commandLine.includes('cdn finder') || commandLine.includes('whatcdn'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cloudflare\.com|akamai\.net|fastly\.net/)) { // Added more CDNs
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cdn info');
        }
    },
    {
        id: 'T1596.005',
        name: 'Search Victim-Owned Websites: Search Engines',
        description: 'Adversaries may use search engines to gather website information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('search engine') || commandLine.includes('google dork') || commandLine.includes('site:'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/google\.com|bing\.com|duckduckgo\.com/)) { // Added more search engines
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('search engine');
        }
    },
    // T1593 - Search Open Websites/Domains
    {
        id: 'T1593',
        name: 'Search Open Websites/Domains',
        description: 'Adversaries may search open websites or domains for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('open website') || commandLine.includes('web scrape') || commandLine.includes('beautifulsoup') || commandLine.includes('scrapy'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.UserAgent?.includes('scraper')) { // Scraper user agents
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('open website');
        }
    },
    {
        id: 'T1593.001',
        name: 'Search Open Websites/Domains: Social Media',
        description: 'Adversaries may search social media for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('social media') || commandLine.includes('twitter api') || commandLine.includes('facebook graph'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/twitter\.com|linkedin\.com|facebook\.com|instagram\.com/)) { // Added more social sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('social media');
        }
    },
    {
        id: 'T1593.002',
        name: 'Search Open Websites/Domains: Search Engines',
        description: 'Adversaries may use search engines to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('search engine') || commandLine.includes('google search') || commandLine.includes('bing api'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/google\.com|bing\.com|yandex\.com/)) { // Added more engines
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('search engine');
        }
    },
    {
        id: 'T1593.003',
        name: 'Search Open Websites/Domains: Code Repositories',
        description: 'Adversaries may search code repositories for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('code repo') || commandLine.includes('github search') || commandLine.includes('gitlab api') || commandLine.includes('bitbucket'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/github\.com|gitlab\.com|bitbucket\.org/)) { // Added more repos
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('code repo');
        }
    },
    // T1594 - Search Closed Sources
    {
        id: 'T1594',
        name: 'Search Closed Sources',
        description: 'Adversaries may search closed sources for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1594/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('closed source') || commandLine.includes('dark web') || commandLine.includes('tor browser') || commandLine.includes('i2p'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/\.onion|torproject\.org/)) { // Tor and dark web indicators
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('closed source');
        }
    },
    // T1597 - Search Open Technical Databases
    {
        id: 'T1597',
        name: 'Search Open Technical Databases',
        description: 'Adversaries may search open technical databases for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1597/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('technical database') || commandLine.includes('shodan search') || commandLine.includes('censys'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cve\.mitre\.org|nvd\.nist\.gov|shodan\.io|censys\.io/)) { // Added more tech DBs
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('technical database');
        }
    },
    {
        id: 'T1597.001',
        name: 'Search Open Technical Databases: DNS/Passive DNS',
        description: 'Adversaries may search DNS or passive DNS databases.',
        mitre_link: 'https://attack.mitre.org/techniques/T1597/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('passive dns') || commandLine.includes('dns lookup') || commandLine.includes('securitytrails') || commandLine.includes('dnshistory'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true;
                }
                if (eid === '22' && commandLine.includes('passive dns')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('passive dns');
        }
    },
    {
        id: 'T1597.002',
        name: 'Search Open Technical Databases: WHOIS',
        description: 'Adversaries may search WHOIS databases.',
        mitre_link: 'https://attack.mitre.org/techniques/T1597/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('whois') || commandLine.includes('whois database') || commandLine.includes('arin.net'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/whois\.org|arin\.net/)) { // Added ARIN
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('whois');
        }
    }
];
