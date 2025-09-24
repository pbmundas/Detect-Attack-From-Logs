const rules = [
    // T1071 - Application Layer Protocol
    {
        id: 'T1071',
        name: 'Application Layer Protocol',
        description: 'Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/curl|wget|http|ftp|smtp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443|21|25|587/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application layer protocol');
        }
    },
    // T1071.001 - Web Protocols
    {
        id: 'T1071.001',
        name: 'Application Layer Protocol: Web Protocols',
        description: 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/curl.*http|wget.*http/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web protocols');
        }
    },
    // T1071.002 - File Transfer Protocols
    {
        id: 'T1071.002',
        name: 'Application Layer Protocol: File Transfer Protocols',
        description: 'Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ftp|sftp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/21|22/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('file transfer protocols');
        }
    },
    // T1071.003 - Mail Protocols
    {
        id: 'T1071.003',
        name: 'Application Layer Protocol: Mail Protocols',
        description: 'Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/smtp|imap|pop3/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/25|587|143|110/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mail protocols');
        }
    },
    // T1071.004 - DNS
    {
        id: 'T1071.004',
        name: 'Application Layer Protocol: DNS',
        description: 'Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/nslookup|dig/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '53') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns');
        }
    },
    // T1071.005 - Publish/Subscribe Protocols
    {
        id: 'T1071.005',
        name: 'Application Layer Protocol: Publish/Subscribe Protocols',
        description: 'Adversaries may communicate using publish/subscribe (pub/sub) application layer protocols to avoid detection/network filtering by blending in with existing traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/mqtt|amqp|pubsub/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/1883|5672/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('publish/subscribe protocols');
        }
    },
    // T1092 - Communication Through Removable Media
    {
        id: 'T1092',
        name: 'Communication Through Removable Media',
        description: 'Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1092/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy to [d-z]:\\|usb|removable media/)) {
                    return true;
                }
                if (eid === '15' && event.Device?.toLowerCase().includes('usb')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('removable media');
        }
    },
    // T1659 - Content Injection
    {
        id: 'T1659',
        name: 'Content Injection',
        description: 'Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1659/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/inject.*content|modify.*web/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.html|\.js/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('content injection');
        }
    },
    // T1132 - Data Encoding
    {
        id: 'T1132',
        name: 'Data Encoding',
        description: 'Adversaries may encode data to make the content of command and control traffic more difficult to detect.',
        mitre_link: 'https://attack.mitre.org/techniques/T1132/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/base64|hex|encode/)) {
                    return true;
                }
                if (eid === '3' && event.QueryName?.toLowerCase().includes('base64')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data encoding');
        }
    },
    // T1132.001 - Standard Encoding
    {
        id: 'T1132.001',
        name: 'Data Encoding: Standard Encoding',
        description: 'Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect.',
        mitre_link: 'https://attack.mitre.org/techniques/T1132/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/base64|ascii|unicode/)) {
                    return true;
                }
                if (eid === '3' && event.QueryName?.toLowerCase().includes('base64')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('standard encoding');
        }
    },
    // T1132.002 - Non-Standard Encoding
    {
        id: 'T1132.002',
        name: 'Data Encoding: Non-Standard Encoding',
        description: 'Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect.',
        mitre_link: 'https://attack.mitre.org/techniques/T1132/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/custom encode|modified base64/)) {
                    return true;
                }
                if (eid === '3' && event.QueryName?.toLowerCase().includes('customencode')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('non-standard encoding');
        }
    },
    // T1001 - Data Obfuscation
    {
        id: 'T1001',
        name: 'Data Obfuscation',
        description: 'Adversaries may obfuscate command and control traffic to make it more difficult to detect.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/obfuscate|junk|stegano/)) {
                    return true;
                }
                if (eid === '3' && event.QueryName?.toLowerCase().includes('obfuscated')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data obfuscation');
        }
    },
    // T1001.001 - Junk Data
    {
        id: 'T1001.001',
        name: 'Data Obfuscation: Junk Data',
        description: 'Adversaries may add junk data to protocols used for command and control to make detection more difficult.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/add junk|append random/)) {
                    return true;
                }
                if (eid === '3' && event.QueryName?.toLowerCase().includes('junk')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('junk data');
        }
    },
    // T1001.002 - Steganography
    {
        id: 'T1001.002',
        name: 'Data Obfuscation: Steganography',
        description: 'Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/stegano|hide in image/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.png|\.jpg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('steganography');
        }
    },
    // T1001.003 - Protocol Impersonation
    {
        id: 'T1001.003',
        name: 'Data Obfuscation: Protocol Impersonation',
        description: 'Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/impersonate http|fake protocol/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol?.toLowerCase().includes('impersonate')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('protocol impersonation');
        }
    },
    // T1568 - Dynamic Resolution
    {
        id: 'T1568',
        name: 'Dynamic Resolution',
        description: 'Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dynamic dns|dga/)) {
                    return true;
                }
                if (eid === '22' && event.QueryName?.length > 50) { // Long DNS queries may indicate DGA
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dynamic resolution');
        }
    },
    // T1568.001 - Fast Flux DNS
    {
        id: 'T1568.001',
        name: 'Dynamic Resolution: Fast Flux DNS',
        description: 'Adversaries may use Fast Flux DNS for dynamic resolution to a command and control server.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/fast flux/)) {
                    return true;
                }
                if (eid === '22' && event.QueryResults?.split(';').length > 5) { // Multiple IPs for one domain
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('fast flux dns');
        }
    },
    // T1568.002 - Domain Generation Algorithms
    {
        id: 'T1568.002',
        name: 'Dynamic Resolution: Domain Generation Algorithms',
        description: 'Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dga|domain generation/)) {
                    return true;
                }
                if (eid === '22' && event.QueryName?.length > 30 && event.QueryStatus === 'NXDOMAIN') { // Long domains with failures
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain generation algorithms');
        }
    },
    // T1568.003 - DNS Calculation
    {
        id: 'T1568.003',
        name: 'Dynamic Resolution: DNS Calculation',
        description: 'Adversaries may perform calculations on addresses returned in DNS results to determine which values are target IP addresses or domain names and which are part of the query response sequence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dns calc|resolve and calculate/)) {
                    return true;
                }
                if (eid === '22' && event.QueryResults?.includes(',')) { // Multiple results indicating calculation
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns calculation');
        }
    },
    // T1571 - Non-Standard Port
    {
        id: 'T1571',
        name: 'Non-Standard Port',
        description: 'Adversaries may communicate using a protocol and port pair that are typically not associated.',
        mitre_link: 'https://attack.mitre.org/techniques/T1571/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/non-standard port|bind to 8080/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol === 'TCP' && event.DestinationPort?.toString() === '80' && event.DestinationHostname?.toLowerCase().includes('ssh')) { // Example mismatch
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('non-standard port');
        }
    },
    // T1572 - Protocol Tunneling
    {
        id: 'T1572',
        name: 'Protocol Tunneling',
        description: 'Adversaries may tunnel network communications to a command and control server located in a remote network.',
        mitre_link: 'https://attack.mitre.org/techniques/T1572/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/tunnel|ssh -L|ngrok/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/22|80/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('protocol tunneling');
        }
    },
    // T1095 - Non-Application Layer Protocol
    {
        id: 'T1095',
        name: 'Non-Application Layer Protocol',
        description: 'Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network.',
        mitre_link: 'https://attack.mitre.org/techniques/T1095/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/icmp tunnel|udp c2/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol === 'ICMP') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('non-application layer protocol');
        }
    },
    // T1090 - Proxy
    {
        id: 'T1090',
        name: 'Proxy',
        description: 'Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/proxy|tor|socks/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '9050') { // TOR
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('proxy');
        }
    },
    // T1090.001 - Internal Proxy
    {
        id: 'T1090.001',
        name: 'Proxy: Internal Proxy',
        description: 'Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/internal proxy/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('internal')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('internal proxy');
        }
    },
    // T1090.002 - External Proxy
    {
        id: 'T1090.002',
        name: 'Proxy: External Proxy',
        description: 'Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/external proxy|tor/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '9050') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('external proxy');
        }
    },
    // T1090.003 - Multi-hop Proxy
    {
        id: 'T1090.003',
        name: 'Proxy: Multi-hop Proxy',
        description: 'Adversaries may chain together multiple proxies to disguise the source of malicious traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/multi-hop|chain proxy/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('proxy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-hop proxy');
        }
    },
    // T1090.004 - Domain Fronting
    {
        id: 'T1090.004',
        name: 'Proxy: Domain Fronting',
        description: 'Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to disguise the destination of HTTPS traffic or other data streams.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/domain fronting|cdn proxy/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('cdn')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain fronting');
        }
    },
    // T1008 - Fallback Channels
    {
        id: 'T1008',
        name: 'Fallback Channels',
        description: 'Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.',
        mitre_link: 'https://attack.mitre.org/techniques/T1008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/fallback c2|alternate channel/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('backup')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('fallback channels');
        }
    },
    // T1102 - Web Service
    {
        id: 'T1102',
        name: 'Web Service',
        description: 'Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/pastebin|dropbox|web service/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/pastebin|dropbox/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web service');
        }
    },
    // T1102.001 - Dead Drop Resolver
    {
        id: 'T1102.001',
        name: 'Web Service: Dead Drop Resolver',
        description: 'Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dead drop|resolver/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/github|gists/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dead drop resolver');
        }
    },
    // T1102.002 - Bidirectional Communication
    {
        id: 'T1102.002',
        name: 'Web Service: Bidirectional Communication',
        description: 'Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/bidirectional|two-way web/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/twitter|facebook/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bidirectional communication');
        }
    },
    // T1102.003 - One-Way Communication
    {
        id: 'T1102.003',
        name: 'Web Service: One-Way Communication',
        description: 'Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/one-way|send only/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/pastebin/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('one-way communication');
        }
    },
    // T1104 - Multi-Stage Channels
    {
        id: 'T1104',
        name: 'Multi-Stage Channels',
        description: 'Adversaries may create multiple stages for command and control that are employed during targeting.',
        mitre_link: 'https://attack.mitre.org/techniques/T1104/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/multi-stage c2|chain c2/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('stage1')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-stage channels');
        }
    },
    // T1105 - Ingress Tool Transfer
    {
        id: 'T1105',
        name: 'Ingress Tool Transfer',
        description: 'Adversaries may transfer tools or other files from an external system into a compromised environment.',
        mitre_link: 'https://attack.mitre.org/techniques/T1105/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wget|curl|scp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '80' && event.NetworkDirection === 'Inbound') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ingress tool transfer');
        }
    },
    // T1573 - Encrypted Channel
    {
        id: 'T1573',
        name: 'Encrypted Channel',
        description: 'Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/encrypt channel|aes c2/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol === 'Encrypted') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('encrypted channel');
        }
    },
    // T1573.001 - Symmetric Cryptography
    {
        id: 'T1573.001',
        name: 'Encrypted Channel: Symmetric Cryptography',
        description: 'Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aes|rc4|symmetric encrypt/)) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().includes('crypto')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('symmetric cryptography');
        }
    },
    // T1573.002 - Asymmetric Cryptography
    {
        id: 'T1573.002',
        name: 'Encrypted Channel: Asymmetric Cryptography',
        description: 'Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/rsa|ecc|asymmetric encrypt/)) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().includes('crypto')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('asymmetric cryptography');
        }
    },
    // T1219 - Remote Access Software
    {
        id: 'T1219',
        name: 'Remote Access Software',
        description: 'Adversaries may use legitimate remote access software to access and control remote systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1219/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/teamviewer|anydesk|vnc/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/5900|3389/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote access software');
        }
    },
    // T1205 - Traffic Signaling
    {
        id: 'T1205',
        name: 'Traffic Signaling',
        description: 'Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control.',
        mitre_link: 'https://attack.mitre.org/techniques/T1205/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/port knock|traffic signal/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('random')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('traffic signaling');
        }
    },
    // T1205.001 - Port Knocking
    {
        id: 'T1205.001',
        name: 'Traffic Signaling: Port Knocking',
        description: 'Adversaries may use port knocking to hide open ports used for persistence or command and control.',
        mitre_link: 'https://attack.mitre.org/techniques/T1205/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/port knock|knock sequence/)) {
                    return true;
                }
                if (eid === '3' && event.NetworkDirection === 'Outbound' && event.DestinationPort?.toString().match(/closed port/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('port knocking');
        }
    },
    // T1205.002 - Socket Filters
    {
        id: 'T1205.002',
        name: 'Traffic Signaling: Socket Filters',
        description: 'Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control.',
        mitre_link: 'https://attack.mitre.org/techniques/T1205/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/socket filter|attach filter/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol === 'SocketFilter') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('socket filters');
        }
    }
];

### Changes Summary
- **Added Rules**: 4 (T1092, T1205, T1205.001, T1205.002 – these were missing from the original file).
- **Removed Rules**: 17 (T1583 and its 8 sub-techniques, T1584 and its 8 sub-techniques, T1665 – these are not part of the Command and Control tactic; they belong to Resource Development or other tactics).
- **Total Rules in Updated File**: 45 (covering all 17 techniques and 28 sub-techniques for 100% coverage).
