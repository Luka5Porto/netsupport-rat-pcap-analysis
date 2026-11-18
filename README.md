# NetSupport RAT Infection: PCAP Analysis Report

**Exercise:** "The Lucky Turkey", Traffic Analysis Exercise dated 2026-11-10 ([malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2026/11/10/index.html))
**Role:** SOC analyst (training exercise)
**Tool:** Wireshark
**Report date:** 2026-11-18

> This is a training exercise using a published, simulated capture. The company, users and hosts are fictional.

---

## 1. Summary

A SOC alert flagged **NetSupport RAT** traffic to `93.152.209[.]36:443`. I reviewed the packet capture from the associated Windows host and **confirmed the alert as a true positive**.

The host `DESKTOP-5OMVI3L` (`10.11.10[.]147`), used by `edward.winslow`, visited a malicious site, downloaded a file from a second server, and about 10 seconds later began communicating with the NetSupport RAT command-and-control (C2) server. It then repeated HTTP POST requests to the C2 roughly once per minute (beaconing).

**Recommended action:** isolate the host, reset the user's credentials, block the C2 and delivery infrastructure, and search for other hosts contacting the same IPs.

---

## 2. Environment

| Item | Value |
|---|---|
| Company | The Lucky Turkey (fictional) |
| LAN | `10.11.10.0/24` |
| Domain | `theluckyturkey[.]com` |
| AD environment | `THELUCKYTURKEY` |
| Domain controller | `10.11.10[.]10` (LUCKYTURKEY-DC) |
| Gateway | `10.11.10[.]1` |

---

## 3. Victim details

| Question | Finding |
|---|---|
| Start of NetSupport RAT traffic | **2026-11-10 18:22:07 UTC** |
| IP address | **10.11.10[.]147** |
| MAC address | **00:12:f0:e5:17:43** |
| Host name | **DESKTOP-5OMVI3L** |
| User account | **edward.winslow** (realm `THELUCKYTURKEY`) |

---

## 4. How I found it

### 4.1 Time and C2 traffic
1. Set **View → Time Display Format → UTC Date and Time of Day**.
2. Filtered `ip.addr == 93.152.209.36`.
3. The first packet is a TCP connection from `10.11.10.147` to port 443. That gives the start time and the victim IP.
4. Followed a TCP stream. The traffic on port 443 is HTTP POST requests to `/fakeurl.htm`, not normal TLS, which is a known NetSupport RAT pattern.

### 4.2 MAC address
Read the **Source** MAC in the Ethernet II header of a packet sent by `10.11.10.147`.

### 4.3 Host name
- Filter: `browser.response_computer_name`
- Windows hosts announce themselves to the LAN (NetBIOS Browser, UDP 138, sent to `10.11.10.255`). This also shows the host's IP and MAC.
- Cross-checked with DHCP / Kerberos computer account (`DESKTOP-5OMVI3L$`).

### 4.4 User account
- Filter: `kerberos.cname_string == 1 and !(kerberos.CNameString contains "$")`
- Kerberos AS-REQ packets from `10.11.10.147` to the DC (port 88) show `CNameString: edward.winslow`. Names ending in `$` are computer accounts and were excluded.

*(More filters in [wireshark-filters.md](wireshark-filters.md).)*

---

## 5. Timeline (UTC, 2026-11-10)

| Time | Event |
|---|---|
| 18:19:55 | Normal Windows connectivity check (`www.msftconnecttest.com`) |
| 18:20:02 | Host announces itself on the LAN (`DESKTOP-5OMVI3L`) |
| 18:20:14 | Kerberos login traffic for `edward.winslow` to the DC |
| 18:21:49 | HTTP GET `/` from **`vericheckusgo[.]com`** (`96.62.224[.]200`) |
| 18:21:59 | HTTP GET `/5555.mp4` from **`96.62.224[.]200`** |
| 18:22:07 | First POST to **`93.152.209[.]36:443`**: NetSupport RAT C2 begins |
| 18:22:08 onward | POST requests to `/fakeurl.htm` about once per minute (beaconing) |

---

## 6. Likely infection chain

> Based on the HTTP traffic before the C2 starts and on the exercise's published answer notes.

1. The user's host requested a page from `vericheckusgo[.]com`. The page returned (15 kB, `text/html`) was exported from the pcap and **flagged as malicious by several vendors on VirusTotal**.
2. The host then downloaded `5555.mp4` (about 6 MB) from `96.62.224[.]200`. The file is **not malicious on its own** per the exercise notes.
3. About 8 seconds later the host started talking to `93.152.209[.]36:443`, the NetSupport RAT C2.

NetSupport Manager is legitimate remote-administration software that attackers abuse as a RAT. It is often signed and may not be flagged by antivirus.

---

## 7. Indicators of Compromise (IOCs)

| Type | Indicator | Context |
|---|---|---|
| IP | `93.152.209[.]36` | NetSupport RAT C2, port 443 |
| URL path | `/fakeurl.htm` | C2 POST path |
| Domain | `vericheckusgo[.]com` | Served the malicious page |
| IP | `96.62.224[.]200` | Hosts `vericheckusgo[.]com` and `5555.mp4` |
| File | `5555.mp4` | Downloaded before the C2 started |
| SHA256 | *(add the hash after exporting the objects in a VM)* | |

---

## 8. Response recommendations

1. Isolate `DESKTOP-5OMVI3L` from the network.
2. Reset the password for `edward.winslow` and review recent logins for that account.
3. Block `93.152.209[.]36`, `96.62.224[.]200` and `vericheckusgo[.]com` at the firewall/DNS.
4. Search logs for other hosts contacting these IOCs.
5. Reimage the host after the investigation.

---

## 9. Screenshots

*(Add your own Wireshark screenshots to a `screenshots/` folder and link them here.)*

- `screenshots/01-first-c2-packet.png`: first packet to `93.152.209.36` with UTC time
- `screenshots/02-host-info.png`: `browser.response_computer_name` result
- `screenshots/03-kerberos-user.png`: Kerberos CNameString
- `screenshots/04-beaconing.png`: POSTs to `/fakeurl.htm` once a minute
- `screenshots/05-http-requests.png`: `vericheckusgo[.]com` and `5555.mp4` requests

---

## 10. What I learned

- Reading Wireshark's time column in UTC and why it matters for reporting.
- Tying together IP, MAC, host name and user using Ethernet headers, NetBIOS and Kerberos.
- Recognizing C2 beaconing: regular, repeated requests to the same server.
- Why port 443 does not always mean real HTTPS.
- Defanging IOCs (`[.]`) so they can't be clicked by accident.

---

*Source of the exercise: [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2026/11/10/index.html). The pcap is not included in this repository.*
