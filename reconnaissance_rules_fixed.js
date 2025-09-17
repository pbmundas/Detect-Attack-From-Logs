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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('nmap') || 
                     commandLine.toLowerCase().includes('scan'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443|22/)) {
                    return true; // Common ports for scanning
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('scan');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('nmap') || 
                     commandLine.toLowerCase().includes('ip scan'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('.')) {
                    return true; // Multiple IP connections
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ip scan');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('nessus') || 
                     commandLine.toLowerCase().includes('vulnerability scan'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/tenable\.com|qualys\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vulnerability scan');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('wordlist') || 
                     commandLine.toLowerCase().includes('dirb') || 
                     commandLine.toLowerCase().includes('gobuster'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('/')) {
                    return true; // Directory scanning
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('wordlist');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('systeminfo') || 
                     commandLine.toLowerCase().includes('wmic'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('systeminfo');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('wmic bios') || 
                     commandLine.toLowerCase().includes('hardware info'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hardware info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('wmic product') || 
                     commandLine.toLowerCase().includes('software info'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('software info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('firmware') || 
                     commandLine.toLowerCase().includes('bios'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('firmware');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('net config') || 
                     commandLine.toLowerCase().includes('client config'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('client config');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName) {
                    return true; // Failed logon attempts
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('credential')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toLowerCase().includes('admin')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('credential harvest')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential harvest');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('email address')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/gmail\.com|outlook\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email address');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('employee name')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('employee name');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('net view') || 
                     commandLine.toLowerCase().includes('network info'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('whois')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/whois\.org/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('whois');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('nslookup') || 
                     commandLine.toLowerCase().includes('dig'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net group')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network trust');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('tracert')) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network topology');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ipconfig')) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ip address');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('firewall info')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/paloaltonetworks\.com|cisco\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('firewall info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('org info')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com|company\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('org info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('location info')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/maps\.google\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('location info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('business relationship')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('business relationship');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('business tempo')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/company\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('business tempo');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('org roles')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/linkedin\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('org roles');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('phishing')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.pdf/)) {
                    return true; // Potential phishing attachments
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('phishing');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('spearphishing service')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/phish\.site/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spearphishing service');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('spearphishing attachment')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.pdf|\.xls/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spearphishing attachment');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('spearphishing link')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spearphishing link');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('voice phishing')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('voice phishing');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('website search')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('website search');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('passive dns') || 
                     commandLine.toLowerCase().includes('dns lookup'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('passive dns');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('whois')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/whois\.org/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('whois');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('certificate info') || 
                     commandLine.toLowerCase().includes('openssl'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/digicert\.com|letsencrypt\.org/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('certificate info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cdn info')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cloudflare\.com|akamai\.net/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cdn info');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('search engine')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/google\.com|bing\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('search engine');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('open website')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('open website');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('social media')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/twitter\.com|linkedin\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('social media');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('search engine')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/google\.com|bing\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('search engine');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('code repo')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/github\.com|gitlab\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code repo');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('closed source')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('tor')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('closed source');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('technical database')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cve\.mitre\.org|nvd\.nist\.gov/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('technical database');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('passive dns') || 
                     commandLine.toLowerCase().includes('dns lookup'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('passive dns');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('whois')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/whois\.org/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('whois');
        }
    }
];