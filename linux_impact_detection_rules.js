// Detection rules for Impact tactic on Linux systems
const rules = [
    // T1486 - Data Encrypted for Impact
    {
        id: 'T1486',
        name: 'Data Encrypted for Impact',
        description: 'Adversaries may encrypt data to disrupt availability.',
        mitre_link: 'https://attack.mitre.org/techniques/T1486/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('openssl') || command.includes('gpg') || command.includes('nmap')) && 
                   description.includes('mass file encryption') && description.includes('ransom artifacts');
        }
    },
    // T1490 - Inhibit System Recovery
    {
        id: 'T1490',
        name: 'Inhibit System Recovery',
        description: 'Adversaries may delete or disable system recovery mechanisms.',
        mitre_link: 'https://attack.mitre.org/techniques/T1490/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('rm') || command.includes('systemctl') || command.includes('bash /tmp/')) && 
                   description.includes('shadow copies') && description.includes('backups deletion');
        }
    },
    // T1485 - Data Destruction
    {
        id: 'T1485',
        name: 'Data Destruction',
        description: 'Adversaries may destroy data to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1485/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('shred') || command.includes('dd if=/dev/zero');
        }
    },
    // T1491 - Defacement
    {
        id: 'T1491',
        name: 'Defacement',
        description: 'Adversaries may deface systems or websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1491/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('echo > /var/www') || command.includes('deface');
        }
    },
    {
        id: 'T1491.002',
        name: 'Defacement: External Defacement',
        description: 'Adversaries may deface external websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1491/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('deface');
        }
    },
    // T1499 - Endpoint Denial of Service
    {
        id: 'T1499',
        name: 'Endpoint Denial of Service',
        description: 'Adversaries may perform DoS attacks on endpoints.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('hping3') || command.includes('slowloris');
        }
    },
    {
        id: 'T1499.002',
        name: 'Endpoint Denial of Service: Service Exhaustion Flood',
        description: 'Adversaries may flood services to cause DoS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('hping3 --flood');
        }
    },
    // T1498 - Network Denial of Service
    {
        id: 'T1498',
        name: 'Network Denial of Service',
        description: 'Adversaries may perform network DoS attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1498/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('hping3') || command.includes('ntp amplification');
        }
    }
];