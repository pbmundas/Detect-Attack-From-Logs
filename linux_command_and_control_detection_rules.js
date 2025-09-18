// Detection rules for Command and Control tactic on Linux systems
const rules = [
    // T1071 - Application Layer Protocol
    {
        id: 'T1071',
        name: 'Application Layer Protocol',
        description: 'Adversaries may use application layer protocols for C2 communication.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('nc') || process.includes('netcat') || command.includes('python -c') || command.includes('curl')) && 
                   description.includes('outbound http post') && description.includes('possible c2');
        }
    },
    {
        id: 'T1071.001',
        name: 'Application Layer Protocol: Web Protocols',
        description: 'Adversaries may use web protocols for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1071.004',
        name: 'Application Layer Protocol: DNS',
        description: 'Adversaries may use DNS for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dig') && event.dst_port?.toString().includes('53');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl s_client') || command.includes('ssh');
        }
    },
    {
        id: 'T1573.001',
        name: 'Encrypted Channel: Symmetric Cryptography',
        description: 'Adversaries may use symmetric cryptography for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl enc');
        }
    },
    {
        id: 'T1573.002',
        name: 'Encrypted Channel: Asymmetric Cryptography',
        description: 'Adversaries may use asymmetric cryptography for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1573/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl x509');
        }
    },
    // T1008 - Fallback Channels
    {
        id: 'T1008',
        name: 'Fallback Channels',
        description: 'Adversaries may use fallback channels for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1008/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('nc') && command.includes('backup');
        }
    },
    // T1105 - Ingress Tool Transfer
    {
        id: 'T1105',
        name: 'Ingress Tool Transfer',
        description: 'Adversaries may transfer tools to a system for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1105/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') || command.includes('curl');
        }
    }
];