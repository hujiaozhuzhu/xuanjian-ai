# A3. Industry-Specific Vertical Vulnerability Rules

## Module: `fp_sentinel/industry_rules/`

26 industry-specific detection rules for 3 new verticals:
- Video Surveillance: 9 rules
- Instant Messaging: 8 rules
- IoT (Internet of Things): 9 rules

All rules extend the Industry enum (now 14 industries total).

## Rule Format (VerticalRule)

```yaml
rule_id: UNIQUE-RULE-001
industry: video_surveillance | instant_messaging | iot
name: Human-readable rule name
category: VULN_CATEGORY
cwe: CWE-XXX
severity: CRITICAL | HIGH | MEDIUM | LOW
owasp: A0X:2021  # optional
description: Detailed description
detection_pattern: Source code pattern guidance
sink_signatures: [dangerous function patterns]
input_signatures: [user input patterns]
tech_targets: [technology labels]
compliance_refs: [Chinese compliance standards]
remediation: Fix guidance
poc_template: Safe PoC verification method
```

## Video Surveillance (9 rules)

Focus areas: ONVIF authentication, RTSP stream encryption,
firmware signing, credential management, P2P relay, cloud storage,
PTZ control, analytics API, edge gateway.

| Rule | Focus | Severity |
|------|-------|----------|
| VS-ONVIF-AUTH-001 | ONVIF WS-UsernameToken replay | CRITICAL |
| VS-RTSP-STREAM-001 | Unencrypted RTSP streams | CRITICAL |
| VS-FIRMWARE-001 | Unsigned firmware updates | CRITICAL |
| VS-DEFAULT-CREDS-001 | Default device credentials | CRITICAL |
| VS-P2P-RELAY-001 | P2P without E2E encryption | HIGH |
| VS-CLOUD-STORAGE-001 | Cloud without client encryption | HIGH |
| VS-PTZ-CONTROL-001 | PTZ without authorization | HIGH |
| VS-ANALYTICS-API-001 | Analytics config injection | MEDIUM |
| VS-EDGE-GATEWAY-001 | Edge gateway management auth | CRITICAL |

## Instant Messaging (8 rules)

Focus areas: E2E encryption, message replay, media sandbox,
group chat access, contact discovery, push security, recall, bot webhook.

| Rule | Focus | Severity |
|------|-------|----------|
| IM-E2E-CRYPTO-001 | Signal Protocol verification | CRITICAL |
| IM-REPLAY-001 | Message replay prevention | HIGH |
| IM-MEDIA-SANDBOX-001 | Media upload sandbox escape | CRITICAL |
| IM-GROUP-ACCESS-001 | Group chat membership check | HIGH |
| IM-CONTACT-DISC-001 | Contact discovery privacy | MEDIUM |
| IM-PUSH-LEAK-001 | Push notification content leak | MEDIUM |
| IM-RECALL-001 | Message recall timing gap | MEDIUM |
| IM-BOT-WEBHOOK-001 | Bot webhook SSRF | HIGH |

## IoT (9 rules)

Focus areas: MQTT auth, CoAP DTLS, OTA signing, device shadow,
sensor integrity, edge gateway, Zigbee keys, digital twin, supply chain.

| Rule | Focus | Severity |
|------|-------|----------|
| IOT-MQTT-AUTH-001 | MQTT anonymous connect | CRITICAL |
| IOT-COAP-SEC-001 | CoAP without DTLS | CRITICAL |
| IOT-OTA-SIGN-001 | OTA firmware signature | CRITICAL |
| IOT-DEVICE-SHADOW-001 | Cross-tenant shadow access | HIGH |
| IOT-SENSOR-INTEGRITY-001 | Sensor data authentication | HIGH |
| IOT-EDGE-GATEWAY-001 | Edge management API auth | HIGH |
| IOT-ZIGBEE-SEC-001 | Network key protection | HIGH |
| IOT-DIGITAL-TWIN-001 | Cross-user twin access | MEDIUM |
| IOT-SUPPLY-CHAIN-001 | Hardware provenance check | MEDIUM |

## Engine API
- `get_vertical_rules(industry) -> VerticalRuleSet`
- `get_rules_by_industry(industry, severity_filter) -> List[VerticalRule]`
- `list_vertical_industries() -> List[str]`
- `count_vertical_rules(industry?) -> int`
