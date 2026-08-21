Output assets/demo-netrecon.svg

Set FontSize 15
Set Width 860
Set Height 380
Set Padding 14
Set Shell bash
Set Theme { "name": "externum", "black": "#0d1117", "red": "#f85149", "green": "#3fb950", "yellow": "#e3b341", "blue": "#58a6ff", "magenta": "#a371f7", "cyan": "#39c5cf", "white": "#e6edf3", "brightBlack": "#8b949e" }

Type 'netrecon 127.0.0.1 22,80,443,8080 --timeout 200'
Enter
Sleep 3500ms

Type 'clear'
Enter
Sleep 300ms
Type 'netrecon --help'
Enter
Sleep 2500ms
