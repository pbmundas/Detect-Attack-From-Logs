// Detection rules for Reconnaissance tactic on Linux systems
const rules = [
    // T1595 - Active Scanning
    {
        id: 'T1595',
        name: 'Active Scanning',
        description: 'Adversaries may execute active reconnaissance scans to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('nmap') || process.includes('masscan') || command.includes('nmap -s') || command.includes('scan')) && 
                   (description.includes('scan') || description.includes('reconnaissance'));
        }
    },
    {
        id: 'T1595.001',
        name: 'Active Scanning: Scanning IP Blocks',
        description: 'Adversaries may scan IP blocks to identify active hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/001/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('nmap') || command.includes('nmap -s') || command.includes('ip scan')) && 
                   event.dst_ip?.toString().includes('.');
        }
    },
    {
        id: 'T1595.002',
        name: 'Active Scanning: Vulnerability Scanning',
        description: 'Adversaries may scan for vulnerabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/002/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('nessus') || process.includes('openvas') || command.includes('vulnerability scan')) && 
                   event.dst_ip?.toString().includes('.');
        }
    },
    {
        id: 'T1595.003',
        name: 'Active Scanning: Wordlist Scanning',
        description: 'Adversaries may use wordlists to scan for resources.',
        mitre_link: 'https://attack.mitre.org/techniques/T1595/003/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('dirb') || process.includes('gobuster') || command.includes('wordlist') || command.includes('dirb'));
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('uname -a') || command.includes('lscpu') || command.includes('dmidecode');
        }
    },
    {
        id: 'T1592.001',
        name: 'Gather Victim Host Information: Hardware',
        description: 'Adversaries may gather hardware information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('lscpu') || command.includes('dmidecode') || command.includes('hwinfo');
        }
    },
    {
        id: 'T1592.002',
        name: 'Gather Victim Host Information: Software',
        description: 'Adversaries may gather software information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dpkg -l') || command.includes('rpm -qa') || command.includes('apt list');
        }
    },
    {
        id: 'T1592.003',
        name: 'Gather Victim Host Information: Firmware',
        description: 'Adversaries may gather firmware information about victim hosts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dmidecode') || command.includes('biosdecode') || command.includes('firmware');
        }
    },
    {
        id: 'T1592.004',
        name: 'Gather Victim Host Information: Client Configurations',
        description: 'Adversaries may gather client configuration information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1592/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('cat /etc/*-release') || command.includes('hostnamectl');
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
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('whoami') || command.includes('id')) && description.includes('credential');
        }
    },
    {
        id: 'T1589.001',
        name: 'Gather Victim Identity Information: Credentials',
        description: 'Adversaries may gather credentials of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('cat /etc/shadow') || command.includes('credential')) && description.includes('credential');
        }
    },
    {
        id: 'T1589.002',
        name: 'Gather Victim Identity Information: Email Addresses',
        description: 'Adversaries may gather email addresses of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('grep -r "@"') || command.includes('email address');
        }
    },
    {
        id: 'T1589.003',
        name: 'Gather Victim Identity Information: Employee Names',
        description: 'Adversaries may gather employee names of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1589/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('getent passwd') || command.includes('employee name');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('netstat') || command.includes('ip addr') || command.includes('ifconfig');
        }
    },
    {
        id: 'T1590.001',
        name: 'Gather Victim Network Information: Domain Properties',
        description: 'Adversaries may gather domain properties of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('whois') || command.includes('dig');
        }
    },
    {
        id: 'T1590.002',
        name: 'Gather Victim Network Information: DNS',
        description: 'Adversaries may gather DNS information of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('nslookup') || command.includes('dig') || event.dst_port?.toString().includes('53');
        }
    },
    {
        id: 'T1590.003',
        name: 'Gather Victim Network Information: Network Trust Dependencies',
        description: 'Adversaries may gather information on network trust dependencies.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('cat /etc/hosts.allow') || command.includes('cat /etc/hosts.deny');
        }
    },
    {
        id: 'T1590.004',
        name: 'Gather Victim Network Information: Network Topology',
        description: 'Adversaries may gather network topology information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('traceroute') || command.includes('mtr');
        }
    },
    {
        id: 'T1590.005',
        name: 'Gather Victim Network Information: IP Addresses',
        description: 'Adversaries may gather IP address information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ip addr') || command.includes('ifconfig');
        }
    },
    {
        id: 'T1590.006',
        name: 'Gather Victim Network Information: Network Security Appliances',
        description: 'Adversaries may gather information on network security appliances.',
        mitre_link: 'https://attack.mitre.org/techniques/T1590/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('iptables -L') || command.includes('ufw status');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('company');
        }
    },
    {
        id: 'T1591.001',
        name: 'Gather Victim Org Information: Determine Physical Locations',
        description: 'Adversaries may gather physical location information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('maps');
        }
    },
    {
        id: 'T1591.002',
        name: 'Gather Victim Org Information: Business Relationships',
        description: 'Adversaries may gather information on business relationships.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('linkedin');
        }
    },
    {
        id: 'T1591.003',
        name: 'Gather Victim Org Information: Identify Business Tempo',
        description: 'Adversaries may identify business tempo of victims.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('calendar');
        }
    },
    {
        id: 'T1591.004',
        name: 'Gather Victim Org Information: Identify Roles',
        description: 'Adversaries may identify roles within victim organizations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1591/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('getent group') || command.includes('org roles');
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
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.includes('wget') && description.includes('phishing');
        }
    },
    {
        id: 'T1598.001',
        name: 'Phishing for Information: Spearphishing Service',
        description: 'Adversaries may use spearphishing services to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('phish');
        }
    },
    {
        id: 'T1598.002',
        name: 'Phishing for Information: Spearphishing Attachment',
        description: 'Adversaries may use spearphishing attachments to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('.pdf');
        }
    },
    {
        id: 'T1598.003',
        name: 'Phishing for Information: Spearphishing Link',
        description: 'Adversaries may use spearphishing links to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1598.004',
        name: 'Phishing for Information: Spearphishing Voice',
        description: 'Adversaries may use voice-based spearphishing to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1598/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('voice phishing');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('website search');
        }
    },
    {
        id: 'T1596.001',
        name: 'Search Victim-Owned Websites: DNS/Passive DNS',
        description: 'Adversaries may search DNS records of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dig') || command.includes('nslookup') || event.dst_port?.toString().includes('53');
        }
    },
    {
        id: 'T1596.002',
        name: 'Search Victim-Owned Websites: WHOIS',
        description: 'Adversaries may search WHOIS records of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('whois');
        }
    },
    {
        id: 'T1596.003',
        name: 'Search Victim-Owned Websites: Digital Certificates',
        description: 'Adversaries may search digital certificates of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl s_client') || command.includes('certificate info');
        }
    },
    {
        id: 'T1596.004',
        name: 'Search Victim-Owned Websites: CDN',
        description: 'Adversaries may search CDN information of victim-owned websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('cdn');
        }
    },
    {
        id: 'T1596.005',
        name: 'Search Victim-Owned Websites: Search Engines',
        description: 'Adversaries may use search engines to gather website information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1596/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('google');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1593.001',
        name: 'Search Open Websites/Domains: Social Media',
        description: 'Adversaries may search social media for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('linkedin');
        }
    },
    {
        id: 'T1593.002',
        name: 'Search Open Websites/Domains: Search Engines',
        description: 'Adversaries may use search engines to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('google');
        }
    },
    {
        id: 'T1593.003',
        name: 'Search Open Websites/Domains: Code Repositories',
        description: 'Adversaries may search code repositories for information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1593/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('git clone') || command.includes('github');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('tor') || command.includes('dark web');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('cve');
        }
    },
    {
        id: 'T1597.001',
        name: 'Search Open Technical Databases: DNS/Passive DNS',
        description: 'Adversaries may search DNS or passive DNS databases.',
        mitre_link: 'https://attack.mitre.org/techniques/T1597/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dig') || command.includes('nslookup') || event.dst_port?.toString().includes('53');
        }
    },
    {
        id: 'T1597.002',
        name: 'Search Open Technical Databases: WHOIS',
        description: 'Adversaries may search WHOIS databases.',
        mitre_link: 'https://attack.mitre.org/techniques/T1597/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('whois');
        }
    }
];