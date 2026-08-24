Output assets/cybersec-demo.gif

Set FontSize 16
Set Width 960
Set Height 420
Set Shell bash
Set Theme "Dracula"

Type "netrecon scanme.nmap.org --ports 1-1000"
Enter
Sleep 1s
Type "   ✓ Scanning 1000 ports..."
Enter
Type "   ✓ 22/tcp   open  ssh"
Enter
Type "   ✓ 80/tcp   open  http"
Enter
Type "   ✓ 443/tcp  open  https"
Enter
Sleep 500ms

Type "hashsleuth 5d41402abc4b2a76b9719d911017c592"
Enter
Sleep 800ms
Type "   🔑 Identified: MD5"
Enter
Type "   ✓ Cracked: 'hello'"
Enter
Sleep 500ms

Type "# 4 Rust security tools · Tokio async · zero deps"
Enter
Sleep 800ms
