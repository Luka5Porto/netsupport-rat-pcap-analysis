# Wireshark Filters Used

Filters from the Lucky Turkey exercise (2026-11-10). Replace IPs and MACs with the ones from your own capture.

## Setup

- **View → Time Display Format → UTC Date and Time of Day**
- **Statistics → Conversations**: see who talked to whom (sort by start time or bytes)
- **Statistics → Endpoints**: list all IPs in the capture

## Find the C2 traffic

| Goal | Filter |
|---|---|
| All traffic to/from the C2 | `ip.addr == 93.152.209.36` |
| POST requests to the C2 | `http.request.method == "POST" && ip.addr == 93.152.209.36` |
| NetSupport user agent | `http.user_agent contains "NetSupport"` |
| Any packet containing "NetSupport" | `frame contains "NetSupport"` |

Then right-click a packet → **Follow → TCP Stream**.

## Identify the victim

| Goal | Filter |
|---|---|
| Host name, IP and MAC together | `browser.response_computer_name` |
| DHCP (Option 12 = host name) | `dhcp && eth.addr == 00:12:f0:e5:17:43` |
| NetBIOS name service | `nbns && ip.src == 10.11.10.147` |
| Computer account (ends in `$`) | `kerberos.CNameString && ip.src == 10.11.10.147` |
| User account (no computer accounts) | `kerberos.cname_string == 1 and !(kerberos.CNameString contains "$")` |
| NTLM logins (backup) | `ntlmssp.auth.username` |
| Everything from one MAC | `eth.src == 00:12:f0:e5:17:43` |

## Find how it got in

| Goal | Filter |
|---|---|
| All HTTP requests from the victim | `http.request && ip.src == 10.11.10.147` |
| TLS server names | `tls.handshake.extensions_server_name` |
| DNS queries from the victim | `dns && ip.src == 10.11.10.147` |

Export downloaded files with **File → Export Objects → HTTP**. Do this inside a VM only, and never open exported files. Hash them (`sha256sum`) and check the hash on VirusTotal instead.

## Tips

- Computer accounts end in `$` in Kerberos. Drop the `$` for the host name.
- Don't use the destination MAC of outbound packets. That is the gateway's MAC.
- Defang IOCs in reports: `93.152.209[.]36`.
