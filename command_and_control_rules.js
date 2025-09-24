const rules = [
    // T1071 - Application Layer Protocol
    {
        id: 'T1071',
        name: 'Application Layer Protocol',
        description: 'Adversaries may use application layer protocols for C2 communication.',
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
    {
        id: 'T1071.001',
        name: 'Application Layer Protocol: Web Protocols',
        description: 'Adversaries may use HTTP/HTTPS for C2 communication.',
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
    {
        id: 'T1071.002',
        name: 'Application Layer Protocol: File Transfer Protocols',
        description: 'Adversaries may use FTP/SFTP for C2 communication.',
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
    {
        id: 'T1071.003',
        name: 'Application Layer Protocol: Mail Protocols',
        description: 'Adversaries may use SMTP/IMAP/POP3 for C2 communication.',
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
    {
        id: 'T1071.004',
        name: 'Application Layer Protocol: DNS',
        description: 'Adversaries may use DNS for C2 communication.',
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
    // T1132 - Data Encoding
    {
        id: 'T1132',
        name: 'Data Encoding',
        description: 'Adversaries may encode C2 data to evade detection.',
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
    {
        id: 'T1132.001',
        name: 'Data Encoding: Standard Encoding',
        description: 'Adversaries may use standard encoding like Base64 for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1132/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/base64|urlencode/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('standard encoding');
        }
    },
    {
        id: 'T1132.002',
        name: 'Data Encoding: Non-Standard Encoding',
        description: 'Adversaries may use non-standard encoding for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1132/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/custom.*encode|obfuscate/)) {
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
        description: 'Adversaries may obfuscate C2 data to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/obfuscate|scramble/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data obfuscation');
        }
    },
    {
        id: 'T1001.001',
        name: 'Data Obfuscation: Junk Data',
        description: 'Adversaries may add junk data to C2 communications.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/junk|padding/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('junk data');
        }
    },
    {
        id: 'T1001.002',
        name: 'Data Obfuscation: Steganography',
        description: 'Adversaries may use steganography for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/steganography|stego/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.png|\.jpg|\.jpeg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('steganography');
        }
    },
    {
        id: 'T1001.003',
        name: 'Data Obfuscation: Protocol Impersonation',
        description: 'Adversaries may impersonate legitimate protocols for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1001/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/impersonate.*protocol/)) {
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
        description: 'Adversaries may use dynamic resolution for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/nslookup|dig.*dynamic/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '53') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dynamic resolution');
        }
    },
    {
        id: 'T1568.001',
        name: 'Dynamic Resolution: Fast Flux DNS',
        description: 'Adversaries may use fast flux DNS for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('fast flux')) {
                    return true;
                }
                if (eid === '3' && event.QueryName && event.DestinationPort?.toString() === '53') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('fast flux dns');
        }
    },
    {
        id: 'T1568.002',
        name: 'Dynamic Resolution: Domain Generation Algorithms',
        description: 'Adversaries may use DGAs for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dga|domain.*generation/)) {
                    return true;
                }
                if (eid === '3' && event.QueryName?.match(/[a-z0-9]{15,}\.[a-z]{2,}/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain generation');
        }
    },
    {
        id: 'T1568.003',
        name: 'Dynamic Resolution: DNS Calculation',
        description: 'Adversaries may use DNS calculations for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1568/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dns.*calc')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '53') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns calculation');
        }
    },
    // T1573 - Encrypted Channel
    {
        id: 'T1573',
        name: 'Encrypted Channel',
        description: 'Adversaries may use encrypted channels for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ssl|tls|encrypt/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '443') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('encrypted channel');
        }
    },
    {
        id: 'T1573.001',
        name: 'Encrypted Channel: Symmetric Cryptography',
        description: 'Adversaries may use symmetric cryptography for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aes|rc4|symmetric/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('symmetric cryptography');
        }
    },
    {
        id: 'T1573.002',
        name: 'Encrypted Channel: Asymmetric Cryptography',
        description: 'Adversaries may use asymmetric cryptography for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/rsa|ecc|asymmetric/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('asymmetric cryptography');
        }
    },
    // T1008 - Fallback Channels
    {
        id: 'T1008',
        name: 'Fallback Channels',
        description: 'Adversaries may use fallback channels for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/fallback|alternate.*channel/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp && event.DestinationPort) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('fallback channels');
        }
    },
    // T1105 - Ingress Tool Transfer
    {
        id: 'T1105',
        name: 'Ingress Tool Transfer',
        description: 'Adversaries may transfer tools to a victim system for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1105/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/curl.*download|wget/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll|\.ps1/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ingress tool transfer');
        }
    },
    // T1104 - Multi-Stage Channels
    {
        id: 'T1104',
        name: 'Multi-Stage Channels',
        description: 'Adversaries may use multi-stage channels for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1104/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/multi-stage|relay/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-stage channels');
        }
    },
    // T1092 - Communication Through Removable Media
    {
        id: 'T1092',
        name: 'Communication Through Removable Media',
        description: 'Adversaries may use removable media for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1092/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*[a-z]:\\|move.*[a-z]:/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/[a-z]:\\.*\.exe|[a-z]:\\.*\.ps1/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('removable media');
        }
    },
    // T1090 - Proxy
    {
        id: 'T1090',
        name: 'Proxy',
        description: 'Adversaries may use proxies for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/proxy|tor|squid/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/8080|3128/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('proxy');
        }
    },
    {
        id: 'T1090.001',
        name: 'Proxy: Internal Proxy',
        description: 'Adversaries may use internal proxies for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/internal.*proxy|squid/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.match(/192\.168\.|10\.|172\./)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('internal proxy');
        }
    },
    {
        id: 'T1090.002',
        name: 'Proxy: External Proxy',
        description: 'Adversaries may use external proxies for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/external.*proxy|tor/)) {
                    return true;
                }
                if (eid === '3' && !event.DestinationIp?.match(/192\.168\.|10\.|172\./)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('external proxy');
        }
    },
    {
        id: 'T1090.003',
        name: 'Proxy: Multi-hop Proxy',
        description: 'Adversaries may use multi-hop proxies for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/multi-hop|tor.*circuit/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-hop proxy');
        }
    },
    {
        id: 'T1090.004',
        name: 'Proxy: Domain Fronting',
        description: 'Adversaries may use domain fronting for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1090/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/domain.*fronting/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/cdn|cloudfront/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain fronting');
        }
    },
    // T1572 - Protocol Tunneling
    {
        id: 'T1572',
        name: 'Protocol Tunneling',
        description: 'Adversaries may tunnel C2 communications through protocols.',
        mitre_link: 'https://attack.mitre.org/techniques/T1572/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ssh.*-L|ngrok|stunnel/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/22|443/)) {
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
        description: 'Adversaries may use non-application layer protocols for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1095/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/icmp|udp.*custom/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol?.toLowerCase().match(/icmp|udp/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('non-application layer protocol');
        }
    },
    // T1571 - Non-Standard Port
    {
        id: 'T1571',
        name: 'Non-Standard Port',
        description: 'Adversaries may use non-standard ports for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1571/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/port.*[0-9]{1,5}/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort && !event.DestinationPort?.toString().match(/80|443|22|21|25|587|143|110|53/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('non-standard port');
        }
    },
    // T1205 - Traffic Signaling
    {
        id: 'T1205',
        name: 'Traffic Signaling',
        description: 'Adversaries may use traffic signaling for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1205/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/signal|beacon/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('traffic signaling');
        }
    },
    {
        id: 'T1205.001',
        name: 'Traffic Signaling: Port Knocking',
        description: 'Adversaries may use port knocking for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1205/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/knock|port.*knock/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/[0-9]{1,5}/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('port knocking');
        }
    },
    {
        id: 'T1205.002',
        name: 'Traffic Signaling: Socket Filters',
        description: 'Adversaries may use socket filters for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1205/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/socket.*filter/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('socket filters');
        }
    },
    // T1102 - Web Service
    {
        id: 'T1102',
        name: 'Web Service',
        description: 'Adversaries may use web services for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/api|webhook/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/api|webhook/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web service');
        }
    },
    {
        id: 'T1102.001',
        name: 'Web Service: Dead Drop Resolver',
        description: 'Adversaries may use dead drop resolvers for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dead.*drop/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dead drop resolver');
        }
    },
    {
        id: 'T1102.002',
        name: 'Web Service: Bidirectional Communication',
        description: 'Adversaries may use web services for bidirectional C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/api.*post|webhook/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '443') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bidirectional communication');
        }
    },
    {
        id: 'T1102.003',
        name: 'Web Service: One-Way Communication',
        description: 'Adversaries may use web services for one-way C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1102/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/api.*get/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '80') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('one-way communication');
        }
    },
    // T1583 - Acquire Infrastructure
    {
        id: 'T1583',
        name: 'Acquire Infrastructure',
        description: 'Adversaries may acquire infrastructure for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws ec2|az vm|register.*domain/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('acquire infrastructure');
        }
    },
    {
        id: 'T1583.001',
        name: 'Acquire Infrastructure: Domains',
        description: 'Adversaries may acquire domains for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/register.*domain|whois/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '43') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('acquire domains');
        }
    },
    {
        id: 'T1583.002',
        name: 'Acquire Infrastructure: DNS Server',
        description: 'Adversaries may acquire DNS servers for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dns.*server|bind/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '53') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns server');
        }
    },
    {
        id: 'T1583.003',
        name: 'Acquire Infrastructure: Virtual Private Server',
        description: 'Adversaries may acquire VPS for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws ec2|az vm|digitalocean/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('virtual private server');
        }
    },
    {
        id: 'T1583.004',
        name: 'Acquire Infrastructure: Server',
        description: 'Adversaries may acquire servers for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/server.*setup/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('acquire server');
        }
    },
    {
        id: 'T1583.005',
        name: 'Acquire Infrastructure: Botnet',
        description: 'Adversaries may acquire botnets for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/botnet|c2.*network/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('botnet');
        }
    },
    {
        id: 'T1583.006',
        name: 'Acquire Infrastructure: Web Services',
        description: 'Adversaries may acquire web services for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/api|webhook/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/api|webhook/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web services');
        }
    },
    {
        id: 'T1583.007',
        name: 'Acquire Infrastructure: Serverless',
        description: 'Adversaries may acquire serverless infrastructure for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws lambda|azure functions/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('serverless');
        }
    },
    {
        id: 'T1583.008',
        name: 'Acquire Infrastructure: Malvertising',
        description: 'Adversaries may use malvertising for C2 infrastructure.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/malvertising|ad.*network/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/ad|advert/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malvertising');
        }
    },
    // T1584 - Compromise Infrastructure
    {
        id: 'T1584',
        name: 'Compromise Infrastructure',
        description: 'Adversaries may compromise infrastructure for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/exploit|compromise.*server/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('compromise infrastructure');
        }
    },
    {
        id: 'T1584.001',
        name: 'Compromise Infrastructure: Domains',
        description: 'Adversaries may compromise domains for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/compromise.*domain/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('compromise domains');
        }
    },
    {
        id: 'T1584.002',
        name: 'Compromise Infrastructure: DNS Server',
        description: 'Adversaries may compromise DNS servers for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dns.*compromise/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '53') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns server compromise');
        }
    },
    {
        id: 'T1584.003',
        name: 'Compromise Infrastructure: Virtual Private Server',
        description: 'Adversaries may compromise VPS for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/vps.*compromise/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('virtual private server compromise');
        }
    },
    {
        id: 'T1584.004',
        name: 'Compromise Infrastructure: Server',
        description: 'Adversaries may compromise servers for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/server.*compromise/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('server compromise');
        }
    },
    {
        id: 'T1584.005',
        name: 'Compromise Infrastructure: Botnet',
        description: 'Adversaries may compromise botnets for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/botnet.*compromise/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('botnet compromise');
        }
    },
    {
        id: 'T1584.006',
        name: 'Compromise Infrastructure: Web Services',
        description: 'Adversaries may compromise web services for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/web.*compromise|api.*exploit/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web services compromise');
        }
    },
    {
        id: 'T1584.007',
        name: 'Compromise Infrastructure: Serverless',
        description: 'Adversaries may compromise serverless infrastructure for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/lambda.*compromise|functions.*exploit/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('serverless compromise');
        }
    },
    {
        id: 'T1584.008',
        name: 'Compromise Infrastructure: Network Devices',
        description: 'Adversaries may compromise network devices for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/router.*exploit|switch.*compromise/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network devices compromise');
        }
    },
    // T1659 - Content Injection
    {
        id: 'T1659',
        name: 'Content Injection',
        description: 'Adversaries may inject content for C2 communication.',
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
    // T1665 - Application Shim
    {
        id: 'T1665',
        name: 'Application Shim',
        description: 'Adversaries may use application shims for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1665/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/sdbinst|shim/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('shim')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application shim');
        }
    }
];
