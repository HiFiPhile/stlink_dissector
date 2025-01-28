# Wireshark ST-Link USB protocol dissector (decoder)

This project provides a Wireshark dissector for the ST-Link USB protocol. The dissector allows you to analyze the communication between ST-Link devices and host computers.


## Installation

1. Clone the repo.
1. Open Wireshark.
2. Go to `Help > About Wireshark` (on Windows or Linux) or `Wireshark > About Wireshark` (on macOS).
3. Select the `Folders` tab.
4. Open the plugin folder by double-clicking the location for the `Global Extcap path`.
5. Copy `stlink.lua` into this folder.

## Example

Output of `example_rtt.pcapng`:

```
ST-LINK  43     1738082072.534255000 Get Version (0xF1)
ST-LINK  33     1738082072.534369000 Payload: 2B5F83045237
ST-LINK  43     1738082072.536068000 Get Current Mode (0xF5)
ST-LINK  29     1738082072.536172000 Mode: MASS
ST-LINK  43     1738082072.537267000 Get Current Mode (0xF5)
ST-LINK  29     1738082072.537333000 Mode: MASS
ST-LINK  43     1738082072.537350000 Get Target Voltage (0xF7)
ST-LINK  35     1738082072.537458000 Target Voltage: 3.22 V
ST-LINK  43     1738082072.553363000 Debug Command (0xF2), Apiv2 SWD Set Freq (0x43)
ST-LINK  29     1738082072.553449000 Status: OK
ST-LINK  43     1738082072.553476000 Debug Command (0xF2), Apiv2 Enter (0x30)
ST-LINK  29     1738082072.554241000 Status: OK
ST-LINK  43     1738082072.554266000 Get Current Mode (0xF5)
ST-LINK  29     1738082072.554348000 Mode: DEBUG
ST-LINK  43     1738082072.556759000 Debug Command (0xF2), Apiv2 Init AP (0x4B), AP: 0
ST-LINK  29     1738082072.556964000 Status: OK
ST-LINK  43     1738082072.558166000 Debug Command (0xF2), Read MEM 32bit (0x07), Addr: 0xE000ED00, Len: 0x0004
ST-LINK  31     1738082072.558324000 Payload: 71C21F41
ST-LINK  43     1738082072.558353000 Debug Command (0xF2), Apiv2 Get last RW status2 (0x3E)
ST-LINK  39     1738082072.558434000 Status: OK
ST-LINK  43     1738082072.559865000 Debug Command (0xF2), Read MEM 32bit (0x07), Addr: 0x20000000, Len: 0x0400
ST-LINK  1051   1738082072.565520000 Payload: 000402400200000001000000020000000300000000000000010000000000...
ST-LINK  43     1738082072.565550000 Debug Command (0xF2), Apiv2 Get last RW status2 (0x3E)
ST-LINK  39     1738082072.565633000 Status: OK
ST-LINK  43     1738082072.565657000 Debug Command (0xF2), Read MEM 32bit (0x07), Addr: 0x20000400, Len: 0x0400
ST-LINK  1051   1738082072.571264000 Payload: 636667312C20676877636667322C20676877636667332C20676877636667...
```