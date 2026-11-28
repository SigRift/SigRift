# Legal Notice and Acceptable Use

SigRift is a software-defined radio (SDR) and technical surveillance
countermeasures (TSCM) platform. It is capable of receiving, demodulating,
classifying, geolocating, and decoding radio-frequency (RF) signals across
a wide range of bands and protocols.

**Radio transmission, reception, and decryption are regulated in every
jurisdiction.** Before using SigRift, you are solely responsible for
understanding and complying with all applicable laws in every jurisdiction
where the software is operated and where its received signals originate.

Use of SigRift without authorization, outside the scope of these terms, or
in violation of applicable law is strictly prohibited. The authors and
contributors accept no liability for misuse.

## 1. Don't

If you skim nothing else, read this. These are the bright lines. The
full prohibited-use list with legal grounding is in §3 below.

- **Don't** decode, decrypt, or disclose your neighbour's Wi-Fi, Bluetooth,
  or cellular traffic.
- **Don't** track AirTags, Tiles, smart-tags, or wearables you do not own.
- **Don't** monitor public-safety, police, fire, EMS, aviation control, or
  maritime distress traffic for content.
- **Don't** decode cellular voice, SMS, or data — anywhere, ever.
- **Don't** jam, spoof, replay, or otherwise transmit on licensed or
  protected services.
- **Don't** conduct covert surveillance of individuals (location, presence,
  device fingerprinting) without informed consent, a court order, or a
  signed assessment engagement.
- **Don't** point SigRift at a network, facility, vehicle, or person
  without written authorization to assess it.
- **Don't** assume "receive only" means "legal" — passive interception is
  a crime in most jurisdictions.
- **Don't** use SigRift to stalk, harass, intimidate, or gather
  intelligence on individuals.
- **Don't** proceed if you cannot name the regulator and statute that
  authorize your specific activity in your specific location.

If you are not certain an activity is lawful where you are, stop and get
written authorization or a regulator opinion before continuing.

## 2. Authorized Use

SigRift is provided for the following lawful purposes only:

- **Defensive TSCM** against RF-borne threats on networks, facilities, or
  property **that you own or are explicitly authorized in writing to assess**.
- **Security research and education** conducted on signals you own, on
  signals in the public domain (e.g., unencrypted public broadcasts such as
  ADS-B, AIS, APRS, and amateur radio where locally permitted), or in
  controlled laboratory environments using signal generators or shielded
  enclosures.
- **Spectrum monitoring and interference hunting** performed by licensed
  operators, regulators, or parties acting under written delegation from a
  regulator.
- **Professional penetration testing and red-team engagements** performed
  under a signed statement of work, rules of engagement, and scope that
  explicitly authorizes RF testing.
- **Amateur radio experimentation** strictly within the privileges of your
  operator licence and local regulation.

## 3. Prohibited Use

You must not use SigRift, and the authors do not authorize the use of
SigRift, for any of the following:

- Intercepting, recording, decoding, or disclosing the contents of any
  **non-public radio communication** you are not a party to or have not
  been explicitly authorized to monitor.
- Circumventing, defeating, or attempting to defeat any **encryption,
  scrambling, or access-control mechanism** protecting a communication
  you are not entitled to access.
- Monitoring, decoding, or interacting with any **cellular, public-safety,
  trunked, aviation control, maritime distress, or emergency-services
  traffic** beyond what is explicitly permitted as receive-only by your
  local regulator (and never for the purpose of obtaining private content).
- **Jamming, spoofing, or otherwise transmitting** any signal that
  interferes with, impersonates, or denies service to a licensed or
  protected radio service. SigRift is a receive-oriented platform; any
  transmit capability in hardware attached to SigRift must be operated
  strictly under your own transmit licence and local regulation.
- **Covert surveillance of individuals** (location tracking, device
  fingerprinting, presence detection) without a lawful basis such as
  informed consent, a court order, or a documented authorized-assessment
  engagement.
- **Industrial espionage, stalking, harassment,** or any activity that
  violates anti-hacking, wiretap, privacy, data-protection, or
  electronic-communications laws.
- Operation in a manner that violates your local regulator's rules on
  spectrum use, radiated power, unintentional radiators, or import/export
  of radio equipment.

Users who violate these restrictions do so on their own legal
responsibility and in violation of this notice.

## 4. Decryption Capability Disclosure

The community edition ships **decryption** for a small set of RF
protocols. Apart from the built-in Meshtastic default-channel keys
described below, SigRift decrypts only with keys you supply. How far
each protocol reaches differs:

- **Meshtastic** payloads (AES-128/256-CTR). This is the **only**
  protocol the product decrypts on its own: through the
  `POST /api/crypto/decrypt` API and in the decode pipeline when stored
  keys match. The result is checked by parsing the plaintext, so a
  wrong key is reported as a failure.
  **Built-in default keys:** SigRift ships the publicly known Meshtastic
  default-channel keys (`AQ==` and the LongFast PSK) and applies them on
  its own, both on the edge scanner (which decodes LoRa frames it
  classifies as Meshtastic or LoRa) and in the bridge decode pipeline.
  Traffic on a default channel (message text, positions, node names) is
  therefore decrypted and stored without any key import. The edge
  scanner's copy of these keys is built in and cannot be turned off in
  this release. The bridge reloads its own copy at every start, so
  deleting the keys through the key API stops only the bridge's use of
  them, and only until the next restart.
- **P25** voice encrypted with DES-OFB (ALGID 0x81) or AES-256-OFB
  (ALGID 0x84), following OP25's keystream construction for FDMA
  (Phase I, LDU1/LDU2) voice codewords. This is a **library-level
  helper only** (`sigrift.lib.crypto.decrypt_p25_phase1` /
  `decrypt_p25_phase2`, which need the message indicator, frame type
  and codeword index): neither the API nor the decode pipeline calls it,
  so importing a P25 key does not make SigRift decrypt P25 traffic.
  Phase II (TDMA) voice is experimental and off by default. P25 results
  are **unverified** (confidence 0): the voice payload carries no
  integrity check, so a wrong key cannot be told apart from the right
  one.
- **DMR**: basic privacy (repeating-key XOR) and DMR AES are
  **library-level, experimental and disabled by default**; they cannot
  be enabled through the API or the decode pipeline, and when a library
  caller enables them explicitly they are unverified (confidence 0) and
  are not expected to recover real over-the-air traffic. Motorola
  Enhanced Privacy (ARC4) is not supported.

All of this is implemented in `src/sigrift/lib/crypto/aes_decrypt.py`.
The key-management API (`src/sigrift/bridge/routers/crypto.py`) stores
keys for any protocol (imported keys are saved in the bridge database,
encrypted with `BRIDGE_KEYSTORE_KEY`, when it is set; revoking a key
deletes its saved row, though copies of the database made earlier keep
it; the built-in keys are never saved), but
`POST /api/crypto/decrypt` and the decode
pipeline (`src/sigrift/bridge/decode_pipeline.py`) only accept a
decryption whose plaintext is verified, which today means Meshtastic
only: a P25 or DMR request to `POST /api/crypto/decrypt` always answers
`"No key produced a confident decryption"`, and the pipeline leaves
stored P25 and DMR messages encrypted. SigRift does not crack,
brute-force, or otherwise recover keys; it applies only the keys the
operator imports and the built-in Meshtastic default-channel keys
described above.

**Lawful scope.** This capability exists solely for traffic you are
entitled to access with keys you are lawfully authorized to hold and
use — your own Meshtastic mesh, a DMR or P25 system you own or
administer, or a system explicitly in scope of a signed assessment
engagement (§2). Because the default-channel keys are applied
automatically, SDR capture near Meshtastic users decodes their
default-channel traffic: make sure that is lawful where you operate.

**Public-safety traffic.** P25 and DMR are predominantly used by
police, fire, EMS, and other public-safety agencies. Decrypting
public-safety — or any other third-party — encrypted traffic without
authorization is a crime in, among others, the United States
(18 U.S.C. §§ 2510–2522; 47 U.S.C. § 605), the United Kingdom
(Wireless Telegraphy Act 2006; Investigatory Powers Act 2016), Canada
(Criminal Code §§ 183–196), Australia (Telecommunications
(Interception and Access) Act 1979), and EU/EEA member states under
national wiretap statutes; see the jurisdictional overview in §5.
Possessing this software does not entitle you to a key, and possessing
a key does not entitle you to use it.

**Wi-Fi capture scope.** When a Wi-Fi adapter is selected (setup
selects a ready spare adapter automatically), the `wifi-scan` service
captures 802.11 management **and data** frames, up to the first 512
bytes of each. On open networks that includes the content of other
people's traffic (for example plaintext web, DNS or IoT payloads), and it
includes WPA handshakes. The scanner sends the bridge only header fields
(addresses, network name, signal), but it holds the most recent 500 raw
frames in memory, and whenever the bridge records a Wi-Fi anomaly it
tries to upload them as a pcap file. In this release the bridge accepts
that upload only from a key with the analyst role or higher, so the
in-stack scanner (which uses the node key `BRIDGE_LOCAL_NODE_KEY`) is
refused and a default install stores no pcap files. A scanner run with
an analyst-role key does store them, and the dashboard then offers them
for download. Stored pcap files are **not** removed by the scheduled
retention cleanup: they stay on the bridge until an administrator runs a
maintenance task that purges them (`purge_pcap_captures`,
`purge_old_data` or `full_cleanup`), and each deletes only files older
than the retention days it is given. Select Wi-Fi capture only where you
are authorized to capture traffic content; otherwise run setup with
`--scanners=sdr`, `--scanners=none` or `--dashboard-only`, so no Wi-Fi
adapter is used.

Nothing in this section permits anything prohibited by §1 or §3. The
export-control treatment of this cryptographic functionality is
covered in §7.

## 5. Jurisdictional Overview

This overview is **informational only**, is **not legal advice**, and is
**not exhaustive**. Laws change. The burden is on you to confirm the
current rules in your jurisdiction.

| Region | Primary authority | Representative constraints |
|---|---|---|
| **United States** | FCC (Title 47 CFR), 18 U.S.C. §§ 2510–2522 (Wiretap Act), 18 U.S.C. § 1029, ECPA | Interception of non-public wire, oral, or electronic communications is a federal crime. Decoding cellular or encrypted communications is prohibited (47 U.S.C. § 605). Amateur operators are bound by Part 97. |
| **United Kingdom** | Ofcom, Wireless Telegraphy Act 2006, Investigatory Powers Act 2016, Computer Misuse Act 1990 | Receiving a message not intended for you and disclosing its existence or content is an offence. Licensed amateurs bound by the UK amateur licence terms. |
| **European Union / EEA** | National regulators (e.g., BNetzA, ARCEP, AGCOM), GDPR, ePrivacy Directive, national wiretap statutes | Passive reception rules vary by member state; decoding and disclosure of private communications is uniformly restricted. RF data that identifies a person is personal data under the GDPR. |
| **Canada** | ISED, Radiocommunication Act, Criminal Code §§ 183–196 | Divulging or using radiocommunication content except as permitted is prohibited. Broad prohibition on unauthorised interception of private communications. |
| **Australia** | ACMA, Radiocommunications Act 1992, Telecommunications (Interception and Access) Act 1979 | Interception of telecommunications carried by a carrier is generally prohibited. ACMA regulates receive and transmit use. |
| **Elsewhere** | National telecom/spectrum regulator, national criminal code | Rules vary significantly. Assume the activity is regulated until you have confirmed otherwise in writing or from an official source. |
| **Anywhere else / unsure** | (not confirmed) | Stop. Do not use SigRift until you have written authorization or a regulator opinion. |

## 6. Data Protection and Privacy

RF observations frequently constitute **personal data** when they can be
associated with an identifiable individual — examples include Wi-Fi MAC
addresses, Bluetooth identifiers, cellular temporary identifiers, vehicle
telemetry, wearable and medical-device telemetry, and any location derived
from them.

When you operate SigRift in a jurisdiction that regulates personal data —
including the EU's General Data Protection Regulation (**GDPR**), the
United Kingdom's data-protection regime (**UK GDPR**), California's
Consumer Privacy Act and Privacy Rights Act (**CCPA/CPRA**), Canada's
Personal Information Protection and Electronic Documents Act (**PIPEDA**),
Australia's Privacy Principles (**APPs**), Brazil's Lei Geral de Proteção
de Dados (**LGPD**), and equivalents — you are the data controller for
the data that SigRift collects on your behalf. You are responsible for:

- Establishing a lawful basis for processing.
- Providing notice where required.
- Limiting collection to what is necessary for the authorized purpose.
- Applying retention limits, access controls, and deletion.
- Handling data-subject requests.
- Reporting personal-data breaches to the relevant supervisory authority
  within the statutory deadline.

SigRift provides technical controls (RBAC, audit logging, configurable
retention). TOTP secrets are encrypted at rest when `BRIDGE_MFA_KEY` is
set (both installers generate it), but the database is not:
SQLCipher is not supported in this release, so use filesystem-level
encryption (for example LUKS) for data at rest. Wi-Fi pcap files, if
your setup stores them, are outside the scheduled retention cleanup (see
§4, "Wi-Fi capture scope"), so include purging them in your retention
routine. None of this absolves
you of these obligations.

## 7. Export Control

SigRift may be subject to export-control and sanctions regimes, including
but not limited to the U.S. EAR, the EU Dual-Use Regulation (2021/821),
and the Wassenaar Arrangement controls on "intrusion software" and
cryptanalytic tooling. You are responsible for ensuring that your
download, use, modification, and redistribution complies with all
applicable export-control and sanctions laws. Do not deploy SigRift in,
or provide it to persons in, jurisdictions subject to comprehensive
sanctions.

## 8. No Warranty; Limitation of Liability

SigRift is licensed under the MIT License. It is provided **"as is", without
warranty of any kind**, express or implied, including merchantability,
fitness for a particular purpose, and non-infringement. See the
[LICENSE](LICENSE) file for the full terms.

In no event will the authors, contributors, or copyright holders be
liable for any claim, damages, fines, regulatory penalties, or other
liability, whether in contract, tort, or otherwise, arising from, out
of, or in connection with the software or its use.

## 9. Reporting Misuse and Security Issues

- **Security vulnerabilities:** see [SECURITY.md](SECURITY.md) for the
  coordinated-disclosure process.
- **Suspected misuse of SigRift in violation of this notice:** report to
  your local law-enforcement or regulatory authority. The SigRift project
  does not investigate third-party misuse and cannot compel third parties
  to stop.

## 10. Acceptance

By downloading, installing, running, modifying, or redistributing SigRift
you acknowledge that you have read this notice, that you are solely
responsible for the legality of your use, and that you accept the terms
of the [LICENSE](LICENSE). Running `scripts/quickstart.sh` or installing
via `docker compose up` constitutes acceptance of these terms.

This notice is an informational statement of acceptable use and a
disclaimer only; it does not modify, condition, or add any restriction
to the rights granted to you by the MIT [LICENSE](LICENSE), which
governs in full.
