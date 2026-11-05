# Do the Gamers Nexus LG findings apply outside the US?

## AI-assisted investigation

### Models used
* Qwen3.8-Uncensored-27B (Orca) for initial rooting assistance
* Opus 5.5 for investigation and this report (with parts redacted manually)

## Context

Tested on: LG OLED42C21LA (EU hardware, board `O22_DVB_EU`), webOS 9.2.2 / firmware 23.25.55, service country **GB** (`countryGroup: EU`), device permanently behind a VPN. 2026-11-05: 25 min in *Active Standby*, then 16 min switched on (home screen → HDMI 1 with a live source → LG Channels). See "TV switched on" below.

Consent state on the TV (and on LG's server, `evidence/eula.json`): **only the mandatory Terms of Use accepted**. ACR/Live Plus, viewing info, voice, interest-based ads, marketing, third-party sharing and "additional data" all declined.

Method: read-only. No settings changed, no partitions remounted. A passive sniffer I wrote, running from `/tmp` (`evidence/sniff.py`), captured the traffic (standby run on the TV; TV-on run streamed to the Mac). The only state change was turning the TV on, switching inputs/apps and putting it back to standby. Configs, binaries and process memory were read through `/proc/<pid>/mem`. Temporary files were removed afterwards.

## Verdict per claim

| Gamers Nexus claim (US) | On this GB/EU-region TV | Confidence |
|---|---|---|
| TV sweeps the LAN and identifies other devices | **Yes, and it goes further.** UEI QuickSet (`iconnectivity`) runs mDNS, SSDP, TP-Link Kasa (`:9999`, including power-meter query) and LIFX (`:56700`) discovery broadcasts, HTTP-probes port 80 on every live host, does a reverse-DNS sweep of all 254 addresses, and pulls UPnP descriptions. | Observed |
| Device identifiers leave the house | **Yes.** `POST https://www.ueiwsp.com/quicksetlite.svc/PredictiveDiscovery` carries per-device **MAC address + mDNS service names/hostnames** (your Macs' and Apple TV's names include your full name). ~118 KB to UEI and ~90 KB to UEI's Azure blob storage in **San Jose, US**, in 25 min of standby. Only the Terms of Use were accepted. | Observed (request body recovered from memory) |
| ACR fingerprints sent to Alphonso / LG Ad Solutions, incl. over HDMI | **Mechanism identical, but consent-gated.** `/tmp/acr.xml` is provisioned for `ACRSolution=ALPHONSO`, `CountryCode=GB`, audio capture from internal loopback. `acr2` is launched only when the EULA allows it. With ACR declined, `acr2` starts for a few seconds at each power-on and input change, checks the EULA and exits. There was **zero** `alphonso.tv` traffic in standby, on the home screen, on HDMI 1 with a live picture, and in LG Channels. The 2024 arXiv study saw `eu-acrX.alphonso.tv` in the UK when users had opted in, and found opt-out works. | Observed (declined, incl. HDMI) / literature (opted in) |
| Nearby Wi-Fi SSIDs and signal strength used for location | **The code is present in the EU build.** The Alphonso SDK (`libas.so`, "lg-webos-24") has `LocationClient() with lat/long and wifiScanOutput`, sorts networks by signal strength, reads the Wi-Fi MAC and postcode, and obeys a server-sent `enable_wifi_scan` flag. It lives inside the ACR client, so it's not active without ACR consent. Not tested in the opted-in state. | Static analysis |
| Traffic to LG ad / customer-data servers before consent | **Yes.** Standby: `GB.nextlgsdp.com` and `GB.info.lgsmartad.com` (AWS Ireland), ~3.5 KB in 25 min. Home screen, first 5 min after power-on: ~33 KB to `gb.nextlgsdp.com`, ~25 KB to `eic.tv.wiselg.com`, ~33 KB to the LG Channels home service, ~11 KB to **`eic.cdpsvc.lgtvcommon.com` (LG's customer-data platform)**, plus `eic.ads.lgtvcommon.com`, Google IMA and DoubleClick. HDMI monitor: ~11 KB to `gb.nextlgsdp.com`. All LG hosts are EU/GB-prefixed. Every LG request tells the server `X-Device-Eula: networkAllowed,chpAllowed,generalTermsAllowed`. `admanager` has EU-specific GDPR/CMP consent-string handling. Contents are TLS-encrypted, so it isn't known what goes to the CDP. | Observed |
| Ads targeted with device IDs, location etc. | **Not with your consent state.** The LG Channels ad request (Ottera SSAI) carries `gdpr=1`, an empty consent string, `is_lat=1`, `ifa_type=sessionid` (no persistent ad ID), an IP truncated to /16, `gender=not_specified`, `yob=0`. It's the US template (it has `us_privacy`/`dnt` slots), filled in GDPR mode. | Observed (request URL from memory) |
| Usage analytics | **Configured even with minimal consent.** PmLogDaemon uses `whitelist_basic.txt` (735 events) when only the general terms are accepted, and the full list (893) once "additional data" is accepted. "Basic" still includes app launches/history, HDMI/CEC, Bluetooth, USB-camera and IoT device lists, search, voice-activation and Wi-Fi-connection events. Uploads go via `sdx` to `gb` LG servers. No sizeable LG upload seen during the standby window. | Static + partial observation |
| Microphone live while the TV looks off | **Yes.** In Active Standby both `WoV PDM Mic` (2ch/16 kHz) and `SpeakerFeedback` (8ch/48 kHz) are `RUNNING` continuously since boot, held by `voiceinput_sound`. The wake-word engines (`trigger_thinq`, `voiceinput_preprocessor`) used ~3 h of CPU in 7.3 h of uptime. Voice terms are **not** accepted, `voiceLongDistance` (far-field) defaults to `on` with no country override, and there's no hardware mic switch (`micSwitchStatus: notsupported`). No voice traffic and no audio files on disk. | Observed |
| "Second microphone" not covered by mute | The `SpeakerFeedback` capture stream exists and runs alongside the main mic. I didn't test whether the menu mic toggle closes it. | Observed (partial) |
| Voice transcripts stored in plain text | Not verifiable here: voice is unused/unconsented, and an anti-spy app purged "ACR/voice residue" on Oct 31. `nlp.cagConfig` from LG's server has `enablePcmDump: true` for the Nuance ASR engine. | Inconclusive |
| "Do Not Sell" off / Limit Ad Tracking off by default | Same factory defaults worldwide (`doNotSell…: off`, `lmt: off`, `adCookie: on`, no GB override). In the GDPR region the real gate is the per-agreement opt-ins, which all default to `false`. This TV currently has `lmt: on`. | Static |
| Residential-proxy SDKs in store apps | None found among your 21 installed apps (string scan). | Static |

## Bottom line

GDPR changes the **defaults and gating**, not the software. The EU/UK firmware ships the same ACR, Wi-Fi-location and analytics machinery as the US, provisioned for GB. The consent-gated parts (ACR, viewing data, ad targeting) really were off here, including with the TV on and used as an HDMI monitor, and LG Channels' ad requests ran in GDPR mode with no ad ID, and LG's servers are told the consent state and are in the EU (AWS Ireland).

The part that **doesn't respect the opt-outs is the LAN mapping.** UEI's QuickSet, a third party, fingerprints every device on your network and sends MAC addresses and device names (containing your name) to UEI's cloud, with storage in the US. It needs only the mandatory Terms of Use, and it runs while the TV is "off". That's the Gamers Nexus finding most clearly reproduced in the EU region. Under GDPR it's personal data processed on the basis of a take-it-or-leave-it ToS.

The always-on standby microphone also applies here, even with voice terms declined. I saw nothing leave the TV, which is consistent with LG's "processed locally" statement, but it isn't opt-in on this unit.

## TV switched on (16-minute capture)

Phases: power-on → home screen (5 min) → HDMI 1 with a live source (5 min) → LG Channels (5 min) → standby.

- **No ACR at any point.** `acr2` appeared for under ~3 s at power-on and on the input switch, then exited. No Alphonso hosts.
- **`livepick` (LG's input overlay/recommendation daemon) starts whenever an HDMI input is selected.** On HDMI the only LG upload was ~11 KB to `gb.nextlgsdp.com`, versus 4 MB+ per hour to Alphonso in the US study.
- **Power-on burst:** within 25 s of turning on, the home screen contacts the LG platform, LG ads, LG's customer-data platform (`eic.cdpsvc.lgtvcommon.com`), Google IMA and DoubleClick, plus YouTube and FAST-channel CDNs.
- **Preloaded third-party apps phone home without being opened.** The suspended Netflix app sent ~280 KB to `logs.netflix.com`, and also does its own DNS via `8.8.8.8:53`, bypassing your router's resolver. YouTube (Cobalt) sent ~57 KB.
- **LG Channels** fetches your public IP from `api.ipify.org`, sends ad requests to Ottera (`stream.ads.ottera.tv`), Google (`pagead2.googlesyndication.com`) and Brightline, and telemetry to `api.axiom.co`. The ad request itself is GDPR-mode, with no ad ID (see table).
- The mic capture stream stayed `RUNNING` throughout (248/248 samples).
- Going to standby after 8+ h of uptime triggered an automatic reboot, which wiped the first TV-on run's capture. The run reported here was streamed off the TV.

## Security issues found (not exploited)

- (REDACTED)
- (REDACTED)

### Note
Redacted as not verified as patched by LG in later firmwares. Nothing major, though.

## Caveats

- One TV, one region (GB, the LG "EU" cluster), ~40 min of traffic in total. No consent-screen (dark-pattern) review: I can't see the screen.
- The opted-in state wasn't tested. It would mean accepting LG/Alphonso terms on your behalf.
- The VPN hides your real IP from LG/UEI, but not the LAN data, MAC addresses or device names in the payloads.
- An earlier anti-spy app (Oct 31) purged some on-device residue. Its hooks are no longer active (verified: no bind mounts, empty iptables, dangling init symlink).
- Not verified: the RCE claims and "audio buffered offline then uploaded". Gamers Nexus demonstrated those on a compromised TV.

## What to do about this

1. Biggest single win: **block `www.ueiwsp.com`, `remotedataupload.blob.core.windows.net` and `discovery.meethue.com`** at the router/DNS (also redirect or block outbound port 53 so apps can't use `8.8.8.8` directly), or put the TV on an isolated VLAN/guest network so it can't see your other devices. The isolation also removes the input data.
2. Rename the devices whose mDNS/AirPlay names contain your full name (Macs, Apple TV, AirPort).
3. Turn off hands-free / far-field voice in *Settings → General → AI Service → Voice recognition settings*, and, if you don't need Quick Start+, *Always Ready*. Then check `/proc/asound/card1/pcm0c/sub0/status` shows `closed` in standby.
4. Keep Live Plus, viewing info, interest-based ads and "additional data" declined, as they are now.

## Evidence (`evidence/`)

- `standby_capture_25min.jsonl`: full metadata capture (DNS, TLS SNI, HTTP request lines, LAN probes, per-flow byte counts).
- `tv_on_capture_16min.jsonl`, `tv_on_marks.txt` (phase times, TV epoch; capture t0 = 1793898244), `tv_on_procs.log` (mic + ACR/ad daemons every 3 s).
- `phases.py`, `adparams.py`: per-phase summary and ad-request parameter extraction.
- `acr.xml`, `eula.json`, `server_addr_version.conf`, `detailconfig.json`: ACR provisioning, server consent record, endpoint map, per-country feature flags.
- `whitelist_basic.txt` / `whitelist.txt`: analytics events allowed at minimal and full consent.
- `sniff.py`, `memgrep.py`, `who_bcast.py`: the read-only tools used.

Sources for the claims: [Notebookcheck](https://www.notebookcheck.net/LG-smart-TVs-caught-logging-audio-with-screen-off-and-snooping-on-local-devices.1391214.0.html), [AdGuard summary](https://adguard-dns.io/en/blog/lg-smart-tv-spying-privacy.html), [Decrypt](https://decrypt.co/377637/lg-tv-might-be-listening-even-when-off), [Malwarebytes](https://www.malwarebytes.com/blog/privacy/2026/09/lg-tv-flaws-could-let-attackers-listen-in-even-in-standby-mode), [arXiv 2409.06203 (UK vs US ACR)](https://arxiv.org/html/2409.06203v1).
