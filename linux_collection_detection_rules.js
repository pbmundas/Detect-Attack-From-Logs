// Detection rules for Collection tactic on Linux systems
const rules = [
    // T1119 - Automated Collection
    {
        id: 'T1119',
        name: 'Automated Collection',
        description: 'Adversaries may automate collection of files from user directories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1119/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('tar -czf') || command.includes('rsync') || command.includes('curl')) && 
                   description.includes('automated collection');
        }
    },
    // T1005 - Data from Local System
    {
        id: 'T1005',
        name: 'Data from Local System',
        description: 'Adversaries may collect data from local systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('cat /home') || command.includes('cp /home');
        }
    },
    // T1113 - Screen Capture
    {
        id: 'T1113',
        name: 'Screen Capture',
        description: 'Adversaries may capture screenshots.',
        mitre_link: 'https://attack.mitre.org/techniques/T1113/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('scrot') || command.includes('import -window');
        }
    },
    // T1115 - Clipboard Data
    {
        id: 'T1115',
        name: 'Clipboard Data',
        description: 'Adversaries may collect clipboard data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1115/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('xclip') || command.includes('pbcopy');
        }
    },
    // T1125 - Video Capture
    {
        id: 'T1125',
        name: 'Video Capture',
        description: 'Adversaries may capture video.',
        mitre_link: 'https://attack.mitre.org/techniques/T1125/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ffmpeg') && command.includes('video');
        }
    },
    // T1213 - Data from Information Repositories
    {
        id: 'T1213',
        name: 'Data from Information Repositories',
        description: 'Adversaries may collect data from information repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('git clone') || command.includes('repository');
        }
    }
];