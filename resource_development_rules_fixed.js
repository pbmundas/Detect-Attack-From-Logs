const rules = [
    // T1583 - Acquire Infrastructure
    {
        id: 'T1583',
        name: 'Acquire Infrastructure',
        description: 'Adversaries may acquire infrastructure to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && // Added PowerShell logging
                    (commandLine.includes('whois') || commandLine.includes('domain registration') || commandLine.includes('godaddy') || commandLine.includes('namecheap') || 
                     parentImage.includes('powershell.exe') || image.includes('whois.exe'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/registrar|godaddy\.com|namecheap\.com|domains\.google/)) { // Added more registrar domains
                    return true;
                }
                if (eid === '22' && commandLine.includes('registrar')) { // DNS queries to registrars
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('domain registration');
        }
    },
    {
        id: 'T1583.001',
        name: 'Acquire Infrastructure: Domains',
        description: 'Adversaries may acquire domains to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('whois') || commandLine.includes('register domain') || commandLine.includes('buy domain') || commandLine.includes('domaintools'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/godaddy\.com|namecheap\.com|domains\.google|enom\.com/)) { // Added more registrars
                    return true;
                }
                if (eid === '22' && commandLine.includes('domain')) { // DNS-related queries
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('register domain');
        }
    },
    {
        id: 'T1583.002',
        name: 'Acquire Infrastructure: DNS Server',
        description: 'Adversaries may acquire DNS servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && // Added script block logging
                    (commandLine.includes('dns server') || commandLine.includes('bind') || commandLine.includes('powerdns') || commandLine.includes('dnsmasq'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53') && event.Protocol?.toLowerCase() === 'udp') { // Refined with protocol
                    return true;
                }
                if (eid === '22' && commandLine.includes('dns')) { // DNS query logging
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dns server');
        }
    },
    {
        id: 'T1583.003',
        name: 'Acquire Infrastructure: Virtual Private Server',
        description: 'Adversaries may acquire VPS to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('vps') || commandLine.includes('aws ec2') || commandLine.includes('digitalocean droplet') || commandLine.includes('linode') || commandLine.includes('vultr'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|digitalocean\.com|linode\.com|vultr\.com/)) { // Added more VPS providers
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('vps');
        }
    },
    {
        id: 'T1583.004',
        name: 'Acquire Infrastructure: Server',
        description: 'Adversaries may acquire servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('server setup') || commandLine.includes('dedicated server') || commandLine.includes('hetzner') || commandLine.includes('ovh'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/hetzner\.com|ovh\.com|rackspace\.com/)) { // Added server providers
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('server setup');
        }
    },
    {
        id: 'T1583.005',
        name: 'Acquire Infrastructure: Botnet',
        description: 'Adversaries may acquire botnets to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('botnet') || commandLine.includes('c2') || commandLine.includes('mirai') || commandLine.includes('necurs'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) && event.User?.toLowerCase() !== 'system') { // Suspicious IPs with user context
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('botnet');
        }
    },
    {
        id: 'T1583.006',
        name: 'Acquire Infrastructure: Web Services',
        description: 'Adversaries may acquire web services to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('web service') || commandLine.includes('cloudflare') || commandLine.includes('heroku') || commandLine.includes('netlify') || commandLine.includes('vercel'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cloudflare\.com|heroku\.com|netlify\.com|vercel\.com/)) { // Added more web services
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('web service');
        }
    },
    // T1584 - Compromise Infrastructure
    {
        id: 'T1584',
        name: 'Compromise Infrastructure',
        description: 'Adversaries may compromise infrastructure to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('compromise') || commandLine.includes('hijack') || commandLine.includes('exploit') || commandLine.includes('vulnerability'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Status?.includes('unauthorized')) { // Added status check if available
                    return true;
                }
                if (eid === '4625') { // Failed logons indicating compromise attempts
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('compromise');
        }
    },
    {
        id: 'T1584.001',
        name: 'Compromise Infrastructure: Domains',
        description: 'Adversaries may compromise domains to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('domain compromise') || commandLine.includes('dns hijack') || commandLine.includes('domain takeover') || commandLine.includes('subdomain hijack'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Protocol?.toLowerCase() === 'dns') {
                    return true;
                }
                if (eid === '22' && commandLine.includes('hijack')) { // DNS queries for hijacking
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dns hijack');
        }
    },
    {
        id: 'T1584.002',
        name: 'Compromise Infrastructure: DNS Server',
        description: 'Adversaries may compromise DNS servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('dns compromise') || commandLine.includes('dns server') || commandLine.includes('bind exploit') || commandLine.includes('dns cache poisoning'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53') && event.Protocol?.toLowerCase() === 'udp') {
                    return true;
                }
                if (eid === '22' && commandLine.includes('dns')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dns compromise');
        }
    },
    {
        id: 'T1584.003',
        name: 'Compromise Infrastructure: Virtual Private Server',
        description: 'Adversaries may compromise VPS to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('vps compromise') || commandLine.includes('aws ec2') || commandLine.includes('ssh brute') || commandLine.includes('rdp exploit'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|digitalocean\.com|linode\.com/) && event.Port?.match(/22|3389/)) { // SSH/RDP ports
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('vps compromise');
        }
    },
    {
        id: 'T1584.004',
        name: 'Compromise Infrastructure: Server',
        description: 'Adversaries may compromise servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('server compromise') || commandLine.includes('server hack') || commandLine.includes('sql injection') || commandLine.includes('rce'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('server') && event.Port?.match(/80|443|1433/)) { // Web/SQL ports
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('server compromise');
        }
    },
    {
        id: 'T1584.005',
        name: 'Compromise Infrastructure: Botnet',
        description: 'Adversaries may compromise botnets to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('botnet compromise') || commandLine.includes('c2') || commandLine.includes('ddos') || commandLine.includes('bot herder'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) && event.Protocol?.toLowerCase() === 'tcp') {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('botnet compromise');
        }
    },
    {
        id: 'T1584.006',
        name: 'Compromise Infrastructure: Web Services',
        description: 'Adversaries may compromise web services to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('web service compromise') || commandLine.includes('cloudflare') || commandLine.includes('api exploit') || commandLine.includes('web shell'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cloudflare\.com|heroku\.com|aws\.amazon\.com/) && event.Port?.match(/80|443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('web service compromise');
        }
    },
    // T1650 - Acquire Access
    {
        id: 'T1650',
        name: 'Acquire Access',
        description: 'Adversaries may purchase or acquire access to compromised systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1650/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('acquire access') || commandLine.includes('dark web') || commandLine.includes('rda purchase') || commandLine.includes('access broker'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/\.onion|torproject\.org|darkmarket/)) { // Dark web indicators
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('acquire access');
        }
    },
    // T1586 - Compromise Accounts
    {
        id: 'T1586',
        name: 'Compromise Accounts',
        description: 'Adversaries may compromise accounts to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1586/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName && event.FailureReason?.includes('unknown user')) { // Refined failed logons
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('account compromise') || commandLine.includes('brute force') || commandLine.includes('credential stuffing'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('account compromise');
        }
    },
    {
        id: 'T1586.001',
        name: 'Compromise Accounts: Social Media Accounts',
        description: 'Adversaries may compromise social media accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1586/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toLowerCase().match(/twitter|facebook|linkedin|instagram/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('social media') || commandLine.includes('account takeover') || commandLine.includes('phishing'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/twitter\.com|facebook\.com|linkedin\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('social media');
        }
    },
    {
        id: 'T1586.002',
        name: 'Compromise Accounts: Email Accounts',
        description: 'Adversaries may compromise email accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1586/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toLowerCase().match(/gmail\.com|outlook\.com|protonmail\.com/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('email compromise') || commandLine.includes('imap exploit') || commandLine.includes('pop3 brute'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/143|993|110|995/)) { // Email ports
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email compromise');
        }
    },
    // T1585 - Establish Accounts
    {
        id: 'T1585',
        name: 'Establish Accounts',
        description: 'Adversaries may create accounts to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1585/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('net user /add') || commandLine.includes('account creation') || commandLine.includes('add-aduser') || commandLine.includes('new-localuser'))) {
                    return true;
                }
                if (eid === '4720' && event.TargetUserName && event.Creator?.toLowerCase() !== 'system') { // User creation with creator context
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('account creation');
        }
    },
    {
        id: 'T1585.001',
        name: 'Establish Accounts: Social Media Accounts',
        description: 'Adversaries may create social media accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1585/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('social media account') || commandLine.includes('twitter') || commandLine.includes('facebook api') || commandLine.includes('instagram signup'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/twitter\.com|facebook\.com|linkedin\.com|instagram\.com/)) { // Added more social platforms
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('social media account');
        }
    },
    {
        id: 'T1585.002',
        name: 'Establish Accounts: Email Accounts',
        description: 'Adversaries may create email accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1585/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('email account') || commandLine.includes('gmail') || commandLine.includes('outlook signup') || commandLine.includes('protonmail'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/gmail\.com|outlook\.com|protonmail\.com|yandex\.com/)) { // Added more email providers
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email account');
        }
    },
    // T1587 - Develop Capabilities
    {
        id: 'T1587',
        name: 'Develop Capabilities',
        description: 'Adversaries may develop capabilities like malware or exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('malware') || commandLine.includes('exploit') || commandLine.includes('payload') || commandLine.includes('obfuscate'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll|\.py|\.ps1/) && event.Creator?.includes('dev')) { // Dev-related creators
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('malware');
        }
    },
    {
        id: 'T1587.001',
        name: 'Develop Capabilities: Malware',
        description: 'Adversaries may develop malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('malware development') || commandLine.includes('ransomware') || commandLine.includes('trojan') || commandLine.includes('virus'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('malware development');
        }
    },
    {
        id: 'T1587.002',
        name: 'Develop Capabilities: Code Signing Certificates',
        description: 'Adversaries may develop or acquire code signing certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('code signing') || commandLine.includes('certificate') || commandLine.includes('signtool') || commandLine.includes('makecert'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.pfx|\.p12/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('code signing');
        }
    },
    {
        id: 'T1587.003',
        name: 'Develop Capabilities: Digital Certificates',
        description: 'Adversaries may develop or acquire digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('digital certificate') || commandLine.includes('openssl') || commandLine.includes('keytool') || commandLine.includes('certbot'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.crt|\.pem|\.key/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('digital certificate');
        }
    },
    {
        id: 'T1587.004',
        name: 'Develop Capabilities: Exploits',
        description: 'Adversaries may develop exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('exploit development') || commandLine.includes('metasploit') || commandLine.includes('canvas') || commandLine.includes('core impact'))) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('exploit')) { // AV detections
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('exploit development');
        }
    },
    // T1588 - Obtain Capabilities
    {
        id: 'T1588',
        name: 'Obtain Capabilities',
        description: 'Adversaries may obtain capabilities like malware or tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('obtain malware') || commandLine.includes('tool download') || commandLine.includes('wget') || commandLine.includes('curl'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll|\.zip|\.rar/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('obtain malware');
        }
    },
    {
        id: 'T1588.001',
        name: 'Obtain Capabilities: Malware',
        description: 'Adversaries may obtain malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('malware download') || commandLine.includes('dark market') || commandLine.includes('ransomware kit'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('malware download');
        }
    },
    {
        id: 'T1588.002',
        name: 'Obtain Capabilities: Tool',
        description: 'Adversaries may obtain tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('tool download') || commandLine.includes('nmap') || commandLine.includes('netcat') || commandLine.includes('mimikatz'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.py|\.bat/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('tool download');
        }
    },
    {
        id: 'T1588.003',
        name: 'Obtain Capabilities: Code Signing Certificates',
        description: 'Adversaries may obtain code signing certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('code signing certificate') || commandLine.includes('buy cert') || commandLine.includes('codesign'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.pfx/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('code signing certificate');
        }
    },
    {
        id: 'T1588.004',
        name: 'Obtain Capabilities: Digital Certificates',
        description: 'Adversaries may obtain digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('digital certificate') || commandLine.includes('certutil') || commandLine.includes('openssl') || commandLine.includes('letsencrypt'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.crt|\.pem|\.key/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('digital certificate');
        }
    },
    {
        id: 'T1588.005',
        name: 'Obtain Capabilities: Exploits',
        description: 'Adversaries may obtain exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('exploit download') || commandLine.includes('metasploit') || commandLine.includes('exploit-db') || commandLine.includes('0day'))) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('exploit')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/exploit-db\.com|packetstormsecurity\.com/)) { // Exploit sites
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('exploit download');
        }
    },
    {
        id: 'T1588.006',
        name: 'Obtain Capabilities: Vulnerabilities',
        description: 'Adversaries may obtain information about vulnerabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('vulnerability scan') || commandLine.includes('nessus') || commandLine.includes('nmap') || commandLine.includes('openvas'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cve\.mitre\.org|nvd\.nist\.gov|tenable\.com/)) { // Added vuln DBs
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('vulnerability scan');
        }
    },
    // T1608 - Stage Capabilities
    {
        id: 'T1608',
        name: 'Stage Capabilities',
        description: 'Adversaries may stage capabilities for use in attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('stage malware') || commandLine.includes('upload') || commandLine.includes('ftp') || commandLine.includes('scp'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll|\.py|\.zip/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('stage malware');
        }
    },
    {
        id: 'T1608.001',
        name: 'Stage Capabilities: Upload Malware',
        description: 'Adversaries may upload malware to stage it for attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('upload malware') || commandLine.includes('ftp') || commandLine.includes('scp') || commandLine.includes('sftp') || commandLine.includes('dropper'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll|\.bin/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('upload malware');
        }
    },
    {
        id: 'T1608.002',
        name: 'Stage Capabilities: Upload Tool',
        description: 'Adversaries may upload tools to stage them for attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('upload tool') || commandLine.includes('nmap') || commandLine.includes('wget') || commandLine.includes('curl') || commandLine.includes('powershell iwr'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.py|\.ps1/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('upload tool');
        }
    },
    {
        id: 'T1608.003',
        name: 'Stage Capabilities: Install Digital Certificate',
        description: 'Adversaries may install digital certificates to stage capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('install certificate') || commandLine.includes('certutil') || commandLine.includes('import-certificate') || commandLine.includes('openssl install'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.crt|\.pem|\.pfx/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('certificates')) { // Registry cert installs
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('install certificate');
        }
    },
    {
        id: 'T1608.004',
        name: 'Stage Capabilities: Drive-by Target',
        description: 'Adversaries may stage capabilities for drive-by attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('drive-by') || commandLine.includes('exploit kit') || commandLine.includes('ek') || commandLine.includes('malvertising'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.UserAgent?.includes('bot')) { // Suspicious user agents
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('drive-by');
        }
    },
    {
        id: 'T1608.005',
        name: 'Stage Capabilities: Link Target',
        description: 'Adversaries may stage capabilities via malicious links.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('malicious link') || commandLine.includes('url') || commandLine.includes('bit.ly') || commandLine.includes('tinyurl') || commandLine.includes('goo.gl'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Referer?.includes('phish')) { // Phishing referers
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('malicious link');
        }
    },
    {
        id: 'T1608.006',
        name: 'Stage Capabilities: SEO Poisoning',
        description: 'Adversaries may use SEO poisoning to stage capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('seo poisoning') || commandLine.includes('search engine') || commandLine.includes('google dork') || commandLine.includes('blackhat seo'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/google\.com|bing\.com|yandex\.com/) && event.Query?.includes('site:')) { // Dorking indicators
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('seo poisoning');
        }
    }
];
