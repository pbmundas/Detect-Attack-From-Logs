const rules = [
    // T1059 - Command and Scripting Interpreter
    {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103' || eid === '4104') && // Added PowerShell logging
                    (image.includes('cmd.exe') || image.includes('powershell.exe') || image.includes('bash') || image.includes('python') || 
                     image.includes('wscript.exe') || image.includes('cscript.exe') || image.includes('perl') || image.includes('ruby') || 
                     commandLine.includes('interpreter') || parentImage.includes('explorer.exe'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cmd') || event.toLowerCase().includes('powershell') || 
                   event.toLowerCase().includes('bash') || event.toLowerCase().includes('python') || event.toLowerCase().includes('vbscript') || 
                   event.toLowerCase().includes('javascript');
        }
    },
    {
        id: 'T1059.001',
        name: 'Command and Scripting Interpreter: PowerShell',
        description: 'Adversaries may abuse PowerShell to execute commands or scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103' || eid === '4104') && 
                    (image.includes('powershell.exe') || commandLine.includes('powershell') || commandLine.includes('pwsh') || 
                     commandLine.includes('invoke-expression') || parentImage.includes('cmd.exe'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('powershell');
        }
    },
    {
        id: 'T1059.002',
        name: 'Command and Scripting Interpreter: AppleScript',
        description: 'Adversaries may abuse AppleScript to execute commands or scripts on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('osascript') || commandLine.includes('applescript') || commandLine.includes('tell application'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.scpt|\.applescript/)) { // AppleScript files
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('osascript');
        }
    },
    {
        id: 'T1059.003',
        name: 'Command and Scripting Interpreter: Windows Command Shell',
        description: 'Adversaries may abuse Windows Command Shell to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('cmd.exe') || commandLine.includes('cmd') || commandLine.includes('start') || commandLine.includes('echo'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.bat') || event.TargetFilename?.toLowerCase().includes('.cmd')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cmd');
        }
    },
    {
        id: 'T1059.004',
        name: 'Command and Scripting Interpreter: Unix Shell',
        description: 'Adversaries may abuse Unix shell to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('bash') || image.includes('sh') || image.includes('zsh') || commandLine.includes('bash') || commandLine.includes('sh -c'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.sh')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('bash');
        }
    },
    {
        id: 'T1059.005',
        name: 'Command and Scripting Interpreter: Visual Basic',
        description: 'Adversaries may abuse Visual Basic scripts to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('wscript.exe') || image.includes('cscript.exe') || commandLine.includes('vbscript') || commandLine.includes('vbs'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.vbs|\.vbe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('vbscript');
        }
    },
    {
        id: 'T1059.006',
        name: 'Command and Scripting Interpreter: Python',
        description: 'Adversaries may abuse Python to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('python') || commandLine.includes('python') || commandLine.includes('pip') || commandLine.includes('py -c'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.py|\.pyc/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('python');
        }
    },
    {
        id: 'T1059.007',
        name: 'Command and Scripting Interpreter: JavaScript',
        description: 'Adversaries may abuse JavaScript to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('wscript.exe') || image.includes('cscript.exe') || image.includes('node.exe') || 
                     commandLine.includes('javascript') || commandLine.includes('js'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.js|\.jse/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('javascript');
        }
    },
    {
        id: 'T1059.008',
        name: 'Command and Scripting Interpreter: Network Device CLI',
        description: 'Adversaries may abuse network device CLI to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('cli') || commandLine.includes('router') || commandLine.includes('switch') || commandLine.includes('cisco') || commandLine.includes('enable'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/22|23|443/) && event.Protocol?.toLowerCase() === 'tcp') { // SSH/Telnet/HTTPS
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cli');
        }
    },
    // T1129 - Shared Modules
    {
        id: 'T1129',
        name: 'Shared Modules',
        description: 'Adversaries may execute malicious code via shared modules like DLLs.',
        mitre_link: 'https://attack.mitre.org/techniques/T1129/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('rundll32.exe') || commandLine.includes('regsvr32.exe') || commandLine.includes('dllhost.exe'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll|\.ocx/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.includes('dll')) { // Registry DLL loads
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('rundll32');
        }
    },
    // T1053 - Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may abuse scheduled tasks or jobs to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('schtasks.exe') || commandLine.includes('schtasks') || commandLine.includes('taskschd') || commandLine.includes('cron'))) {
                    return true;
                }
                if ((eid === '4698' || eid === '4699' || eid === '4702') && event.TaskName) { // Task creation/update/deletion
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('schtasks');
        }
    },
    {
        id: 'T1053.002',
        name: 'Scheduled Task/Job: At',
        description: 'Adversaries may use the at command to schedule tasks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('at.exe') || commandLine.includes('at ') || commandLine.includes('atd'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('at ');
        }
    },
    {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        description: 'Adversaries may use scheduled tasks to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('schtasks /create') || commandLine.includes('register-scheduledtask') || image.includes('taskschd.msc'))) {
                    return true;
                }
                if (eid === '4698' && event.TaskName && event.User?.toLowerCase() !== 'system') { // Task creation with user context
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('schtasks /create');
        }
    },
    // T1053.006 - Scheduled Task/Job: Systemd Timers
    {
        id: 'T1053.006',
        name: 'Scheduled Task/Job: Systemd Timers',
        description: 'Adversaries may use systemd timers to execute code on Linux.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('systemd-run') || commandLine.includes('timer') || commandLine.includes('systemctl enable'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.timer|\.service/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('systemd-run');
        }
    },
    // T1053.007 - Scheduled Task/Job: Container Orchestration Job
    {
        id: 'T1053.007',
        name: 'Scheduled Task/Job: Container Orchestration Job',
        description: 'Adversaries may use container orchestration jobs to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('kubectl create cronjob') || commandLine.includes('kubernetes job') || commandLine.includes('docker schedule'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.yaml') && commandLine.includes('cronjob')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('kubectl create cronjob');
        }
    },
    // T1204 - User Execution
    {
        id: 'T1204',
        name: 'User Execution',
        description: 'Adversaries may rely on user execution to run malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('user execution') || image.includes('explorer.exe') || commandLine.includes('open'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.docx|\.pdf/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('user execution');
        }
    },
    {
        id: 'T1204.001',
        name: 'User Execution: Malicious Link',
        description: 'Adversaries may use malicious links to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('malicious link') || commandLine.includes('url') || commandLine.includes('http') || commandLine.includes('bit.ly'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Referer?.includes('phish')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('malicious link');
        }
    },
    {
        id: 'T1204.002',
        name: 'User Execution: Malicious File',
        description: 'Adversaries may use malicious files to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.match(/\.exe|\.docx|\.pdf/) || commandLine.includes('open') || commandLine.includes('start'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.docx|\.pdf|\.xls|\.rtf/)) {
                    return true;
                }
                if (eid === '1116' && event.Message?.includes('malicious file')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('malicious file');
        }
    },
    {
        id: 'T1204.003',
        name: 'User Execution: Malicious Image',
        description: 'Adversaries may use malicious container images to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('docker') || commandLine.includes('container') || commandLine.includes('docker run') || commandLine.includes('podman'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/dockerfile|\.tar/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('docker');
        }
    },
    // T1569 - System Services
    {
        id: 'T1569',
        name: 'System Services',
        description: 'Adversaries may abuse system services to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1569/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('sc.exe') || commandLine.includes('sc create') || commandLine.includes('new-service') || commandLine.includes('installutil'))) {
                    return true;
                }
                if ((eid === '7045' || eid === '7036') && event.ServiceName && event.User?.toLowerCase() !== 'system') { // Service creation/start
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sc create');
        }
    },
    {
        id: 'T1569.001',
        name: 'System Services: Launchctl',
        description: 'Adversaries may use launchctl to execute code on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1569/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('launchctl') || commandLine.includes('launchctl') || commandLine.includes('launchd') || commandLine.includes('plist'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('launchctl');
        }
    },
    {
        id: 'T1569.002',
        name: 'System Services: Service Execution',
        description: 'Adversaries may execute code via system services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1569/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('sc.exe') || commandLine.includes('sc start') || commandLine.includes('net start') || commandLine.includes('start-service'))) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sc start');
        }
    },
    // T1047 - Windows Management Instrumentation
    {
        id: 'T1047',
        name: 'Windows Management Instrumentation',
        description: 'Adversaries may abuse WMI to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1047/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('wmiprvse.exe') || commandLine.includes('wmic') || commandLine.includes('wmi') || commandLine.includes('get-wmiobject'))) {
                    return true;
                }
                if (eid === '5859' || eid === '5861') { // WMI event IDs
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('wmic');
        }
    },
    // T1609 - Container Administration Command
    {
        id: 'T1609',
        name: 'Container Administration Command',
        description: 'Adversaries may abuse container administration commands to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1609/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('docker') || commandLine.includes('kubectl') || commandLine.includes('podman') || commandLine.includes('containerd'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('docker');
        }
    },
    // T1610 - Deploy Container
    {
        id: 'T1610',
        name: 'Deploy Container',
        description: 'Adversaries may deploy containers to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1610/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('docker run') || commandLine.includes('kubectl apply') || commandLine.includes('docker-compose up') || commandLine.includes('podman run'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/dockerfile|\.yaml/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('docker run');
        }
    },
    // T1203 - Exploitation for Client Execution
    {
        id: 'T1203',
        name: 'Exploitation for Client Execution',
        description: 'Adversaries may exploit software vulnerabilities to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1203/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('exploit') || commandLine.includes('cve') || commandLine.includes('metasploit') || commandLine.includes('shellcode'))) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('exploit')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('exploit');
        }
    },
    // T1559 - Inter-Process Communication
    {
        id: 'T1559',
        name: 'Inter-Process Communication',
        description: 'Adversaries may use inter-process communication to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1559/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('com') || commandLine.includes('dde') || commandLine.includes('ipc') || commandLine.includes('pipe'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('com');
        }
    },
    {
        id: 'T1559.001',
        name: 'Inter-Process Communication: Component Object Model',
        description: 'Adversaries may use COM to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1559/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('mmc.exe') || commandLine.includes('com') || commandLine.includes('ole') || commandLine.includes('cocreateinstance'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('com');
        }
    },
    {
        id: 'T1559.002',
        name: 'Inter-Process Communication: Dynamic Data Exchange',
        description: 'Adversaries may use DDE to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1559/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('dde') || commandLine.includes('ddeexec') || commandLine.includes('dynamic data exchange'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.xlsx/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dde');
        }
    },
    // T1620 - Software Deployment Tools
    {
        id: 'T1620',
        name: 'Software Deployment Tools',
        description: 'Adversaries may use software deployment tools to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1620/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('msiexec') || commandLine.includes('sccm') || commandLine.includes('pdqdeploy') || commandLine.includes('ansible'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.msi|\.pkg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('msiexec');
        }
    }
];
