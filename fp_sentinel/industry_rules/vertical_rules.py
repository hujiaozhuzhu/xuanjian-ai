"""
V3.1 Industry-Specific Vulnerability Rules for Three New Verticals

Video Surveillance (9 rules): ONVIF auth, RTSP stream protection, firmware signing,
credential defaults, P2P relay security, cloud storage encryption, PTZ control auth,
video analytics API vuln, edge gateway bypass

Instant Messaging (8 rules): E2E encryption verification, message replay protection,
media file sandbox, group chat access control, contact discovery privacy,
push notification leak, message recall security, bot webhook validation

IoT (9 rules): MQTT auth, CoAP security, OTA firmware signing, device shadow auth,
sensor data integrity, edge computing gateway, Zigbee/LoRaWAN security,
digital twin auth, supply chain provenance
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class VerticalIndustry(str, Enum):
    VIDEO_SURVEILLANCE = "video_surveillance"
    INSTANT_MESSAGING = "instant_messaging"
    IOT = "iot"


class VerticalRule(BaseModel):
    """A single industry-specific vulnerability detection rule."""
    model_config = {"extra": "forbid"}

    rule_id: str = Field(..., description="Unique rule identifier")
    industry: str = Field(..., description="Industry this rule applies to")
    name: str = Field(..., description="Human-readable rule name")
    category: str = Field(..., description="Vulnerability category")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    severity: str = Field("HIGH", description="CRITICAL/HIGH/MEDIUM/LOW")
    owasp: Optional[str] = Field(None, description="OWASP Top 10 reference")
    description: str = Field("", description="Detailed rule description")
    detection_pattern: str = Field("", description="Detection pattern/guidance")
    sink_signatures: List[str] = Field(default_factory=list,
                                       description="Dangerous function patterns")
    input_signatures: List[str] = Field(default_factory=list,
                                       description="User input patterns")
    tech_targets: List[str] = Field(default_factory=list,
                                    description="Target technology labels")
    compliance_refs: List[str] = Field(default_factory=list,
                                      description="Compliance references")
    remediation: str = Field("", description="Suggested fix guidance")
    poc_template: str = Field("", description="Safe PoC verification method")
    enabled: bool = Field(True, description="Whether rule is active")


class VerticalRuleSet(BaseModel):
    """A set of rules for one industry vertical."""
    model_config = {"extra": "forbid"}

    industry: str = Field(..., description="Industry vertical")
    version: str = Field("3.1.0", description="Rule set version")
    rules: List[VerticalRule] = Field(default_factory=list)
    description: str = Field("", description="Industry description")

    @property
    def enabled_rules(self) -> List[VerticalRule]:
        return [r for r in self.rules if r.enabled]

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.rules if r.severity == "CRITICAL" and r.enabled)

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.rules if r.severity == "HIGH" and r.enabled)


# ============================================================
# VIDEO SURVEILLANCE RULES (9 rules)
# ============================================================

_VIDEO_SURVEILLANCE_RULES = [
    VerticalRule(
        rule_id="VS-ONVIF-AUTH-001",
        industry="video_surveillance",
        name="ONVIF WS-UsernameToken Authentication Bypass",
        category="AUTH_BYPASS",
        cwe="CWE-287",
        severity="CRITICAL",
        owasp="A07:2021",
        description="ONVIF device authentication using WS-UsernameToken without proper "
                    "nonce verification or replay protection allows authentication bypass",
        detection_pattern="Check ONVIF Digest authentication implementation for "
                         "nonce freshness validation and replay detection",
        sink_signatures=["onvif_auth", "wsse_verify", "digest_auth", "UsernameToken"],
        input_signatures=["nonce", "created", "password_digest"],
        tech_targets=["ONVIF", "RTSP", "IP Camera"],
        compliance_refs=["GB/T 28181-2022", "GB 35114-2017"],
        remediation="Implement proper nonce freshness checking with 5-minute window "
                    "and server-side nonce cache with replay detection",
        poc_template="ONVIF replay test with captured nonce (harmless marker)",
    ),
    VerticalRule(
        rule_id="VS-RTSP-STREAM-001",
        industry="video_surveillance",
        name="Unencrypted RTSP Media Stream Exposure",
        category="DATA_EXPOSURE",
        cwe="CWE-319",
        severity="CRITICAL",
        owasp="A02:2021",
        description="RTSP video streams transmitted without SRTP/RTSPS encryption, "
                    "allowing network sniffing of surveillance footage",
        detection_pattern="Detect RTSP URLs without rtsps:// or SRTP configuration",
        sink_signatures=["rtsp://", "RTP", "live555", "gst-rtsp-server"],
        input_signatures=["stream_url", "media_uri"],
        tech_targets=["RTSP", "RTMP", "HLS", "WebRTC", "IP Camera"],
        compliance_refs=["GB/T 28181-2022 6.3", "GB 35114-2017"],
        remediation="Enable RTSPS (RTSP over TLS) and configure SRTP for media encryption",
        poc_template="RTSP URL scan with network capture check (passive)",
    ),
    VerticalRule(
        rule_id="VS-FIRMWARE-001",
        industry="video_surveillance",
        name="Unsigned Firmware Update Verification Missing",
        category="INTEGRITY_FAILURE",
        cwe="CWE-352",
        severity="CRITICAL",
        description="Camera firmware updates accepted without cryptographic signature "
                    "verification allows supply chain compromise",
        detection_pattern="Check firmware update endpoint for signature validation",
        sink_signatures=["firmware_upgrade", "firmware_update", "ota_handler"],
        input_signatures=["firmware_file", "version", "checksum"],
        tech_targets=["IP Camera", "DVR", "NVR", "Edge Gateway"],
        compliance_refs=["GB/T 36627-2018", "GB 35114-2017 6.2"],
        remediation="Implement Ed25519 firmware signature verification before flashing, "
                    "with rollback protection via monotonic counter",
        poc_template="Firmware header inspection (harmless)",
    ),
    VerticalRule(
        rule_id="VS-DEFAULT-CREDS-001",
        industry="video_surveillance",
        name="Hardcoded/Default Device Credentials",
        category="HARDCODED_CREDENTIALS",
        cwe="CWE-798",
        severity="CRITICAL",
        owasp="A07:2021",
        description="Surveillance devices with hardcoded default credentials "
                    "(admin/admin, root/12345) enabling mass botnet enrollment",
        detection_pattern="Search for hardcoded credentials and default password lists",
        sink_signatures=["admin", "root", "12345", "default_password", "factory_reset"],
        input_signatures=["username", "password", "auth_token"],
        tech_targets=["IP Camera", "NVR", "VMS"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4"],
        remediation="Force password change on initial setup, implement per-device "
                    "unique default credentials printed on device label",
        poc_template="Default credential check against known patterns (harmless)",
    ),
    VerticalRule(
        rule_id="VS-P2P-RELAY-001",
        industry="video_surveillance",
        name="P2P Relay Without End-to-End Encryption",
        category="CRYPTO_FAILURE",
        cwe="CWE-327",
        severity="HIGH",
        description="Cloud P2P relay for camera remote access transmits video without "
                    "E2E encryption, enabling cloud operator surveillance",
        detection_pattern="Check P2P implementation for E2E key exchange",
        sink_signatures=["p2p_connect", "relay_server", "stun_turn", "ice_candidate"],
        input_signatures=["peer_id", "session_key"],
        tech_targets=["P2P", "Cloud Camera", "STUN", "TURN"],
        compliance_refs=["个人信息保护法-第51条"],
        remediation="Implement WebRTC DTLS-SRTP for P2P sessions with certificate pinning",
        poc_template="P2P traffic encryption verification (passive)"
    ),
    VerticalRule(
        rule_id="VS-CLOUD-STORAGE-001",
        industry="video_surveillance",
        name="Cloud Video Storage Without Client-Side Encryption",
        category="DATA_PROTECTION",
        cwe="CWE-311",
        severity="HIGH",
        description="Video clips uploaded to cloud storage without client-side encryption, "
                    "exposing footage to cloud provider access",
        detection_pattern="Check cloud upload pipeline for encryption before transmission",
        sink_signatures=["s3_upload", "blob_upload", "cloud_store", "oss_put"],
        input_signatures=["video_clip", "recording"],
        tech_targets=["AWS S3", "Aliyun OSS", "Cloud Storage"],
        compliance_refs=["GB/T 35273-2020", "个人信息保护法-第51条"],
        remediation="Implement AES-256-GCM client-side encryption before cloud upload "
                    "with user-controlled keys",
        poc_template="Upload encryption check (harmless marker)"
    ),
    VerticalRule(
        rule_id="VS-PTZ-CONTROL-001",
        industry="video_surveillance",
        name="PTZ Control Without Authorization Check",
        category="BROKEN_ACCESS_CONTROL",
        cwe="CWE-862",
        severity="HIGH",
        description="Pan-Tilt-Zoom camera control API lacks per-camera authorization, "
                    "allowing any authenticated user to control any camera",
        detection_pattern="Verify PTZ API enforces camera-level access control",
        sink_signatures=["ptz_control", "ptz_move", "ptz_preset", "onvif_ptz"],
        input_signatures=["camera_id", "preset_id", "pan", "tilt"],
        tech_targets=["ONVIF PTZ", "IP Camera", "VMS"],
        compliance_refs=["GB/T 28181-2022 7.3"],
        remediation="Add camera-level RBAC to all PTZ control endpoints",
        poc_template="Cross-camera PTZ access test (harmless)"
    ),
    VerticalRule(
        rule_id="VS-ANALYTICS-API-001",
        industry="video_surveillance",
        name="Video Analytics API Injection Vulnerability",
        category="INJECTION",
        cwe="CWE-94",
        severity="MEDIUM",
        description="AI analytics configuration API that processes user-supplied model "
                    "parameters without validation allows code injection",
        detection_pattern="Check analytics API validates model parameters against whitelist",
        sink_signatures=["inference_config", "model_params", "analytics_pipeline"],
        input_signatures=["threshold", "model_path", "config_json"],
        tech_targets=["AI Analytics", "Edge AI", "Video Analytics"],
        compliance_refs=["GB/T 22239-2019 三级8.1.3"],
        remediation="Validate all analytics parameters against schema, restrict model "
                    "paths to approved directory",
        poc_template="Parameter fuzzing with valid values (harmless)"
    ),
    VerticalRule(
        rule_id="VS-EDGE-GATEWAY-001",
        industry="video_surveillance",
        name="Edge Computing Gateway Authentication Bypass",
        category="AUTH_BYPASS",
        cwe="CWE-287",
        severity="CRITICAL",
        description="Edge computing gateway for local video processing exposes management "
                    "API without authentication on local network",
        detection_pattern="Check edge gateway management API requires authentication",
        sink_signatures=["edge_management", "local_api", "gateway_config"],
        input_signatures=["device_id", "gateway_ip"],
        tech_targets=["Edge Gateway", "Edge Computing", "MEC"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4", "GB 35114-2017"],
        remediation="Enable mTLS authentication for all edge management endpoints",
        poc_template="Edge API auth probe (harmless)"
    ),
]


# ============================================================
# INSTANT MESSAGING RULES (8 rules)
# ============================================================

_INSTANT_MESSAGING_RULES = [
    VerticalRule(
        rule_id="IM-E2E-CRYPTO-001",
        industry="instant_messaging",
        name="End-to-End Encryption Implementation Verification",
        category="CRYPTO_FAILURE",
        cwe="CWE-327",
        severity="CRITICAL",
        owasp="A02:2021",
        description="Instant messaging app claims E2E encryption but uses weak "
                    "algorithms, incorrect key exchange, or stores keys improperly",
        detection_pattern="Verify Signal Protocol double ratchet implementation, "
                         "check key storage in secure enclave",
        sink_signatures=["signal_protocol", "double_ratchet", "x3dh", "curve25519"],
        input_signatures=["session_key", "identity_key", "prekey"],
        tech_targets=["Signal Protocol", "Matrix", "XMPP", "IM SDK"],
        compliance_refs=["GB/T 39786-2021", "个人信息保护法-第51条"],
        remediation="Use audited Signal Protocol library, store keys in device "
                    "secure enclave (TEE/SE)",
        poc_template="Key exchange flow inspection (harmless)"
    ),
    VerticalRule(
        rule_id="IM-REPLAY-001",
        industry="instant_messaging",
        name="Message Replay Attack Prevention Missing",
        category="REPLAY_ATTACK",
        cwe="CWE-294",
        severity="HIGH",
        description="Message delivery lacks sequence numbers or timestamps, "
                    "allowing replay of captured messages",
        detection_pattern="Check message deduplication via sequence numbers or HMAC",
        sink_signatures=["message_handler", "deliver_message", "push_notification"],
        input_signatures=["message_id", "seq_num", "timestamp", "nonce"],
        tech_targets=["IM Server", "Message Queue"],
        compliance_refs=["GB/T 22239-2019 三级8.1.3"],
        remediation="Implement message sequence numbers with sliding window dedup "
                    "and timestamp-based expiration",
        poc_template="Message replay simulation with captured seq (harmless)"
    ),
    VerticalRule(
        rule_id="IM-MEDIA-SANDBOX-001",
        industry="instant_messaging",
        name="Media File Upload Sandbox Escape Prevention",
        category="SANDBOX_ESCAPE",
        cwe="CWE-434",
        severity="CRITICAL",
        description="Uploaded images/videos/gifs not processed in sandboxed environment "
                    "allow steganography-based or parsing-vulnerability attacks",
        detection_pattern="Check media processing uses isolated sandbox or re-encoding",
        sink_signatures=["media_upload", "thumbnail_gen", "file_processor"],
        input_signatures=["image", "video", "gif", "attachment"],
        tech_targets=["IM File Server", "Chat App"],
        compliance_refs=["GB/T 22239-2019 三级8.1.3"],
        remediation="Re-encode all uploaded media using sandboxed ffmpeg/ImageMagick "
                    "in isolated containers",
        poc_template="Image metadata preservation check (harmless)"
    ),
    VerticalRule(
        rule_id="IM-GROUP-ACCESS-001",
        industry="instant_messaging",
        name="Group Chat Access Control Enforcement",
        category="BROKEN_ACCESS_CONTROL",
        cwe="CWE-862",
        severity="HIGH",
        description="Group chat messages accessible without verifying group membership, "
                    "allowing ex-members or non-members to read group history",
        detection_pattern="Verify group message API checks group membership",
        sink_signatures=["group_message", "group_send", "group_history"],
        input_signatures=["group_id", "user_id"],
        tech_targets=["Group Chat", "IM Server"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4"],
        remediation="Add group membership verification to all group message endpoints "
                    "with server-side enforcement",
        poc_template="Cross-group message access test (harmless)"
    ),
    VerticalRule(
        rule_id="IM-CONTACT-DISC-001",
        industry="instant_messaging",
        name="Contact Discovery Privacy Leakage",
        category="PRIVACY_VIOLATION",
        cwe="CWE-215",
        severity="MEDIUM",
        description="Contact matching API leaks whether registered users exist, "
                    "enabling social graph enumeration",
        detection_pattern="Check contact discovery API response does not differentiate "
                         "existing vs non-existing users",
        sink_signatures=["contact_match", "phone_lookup", "user_search"],
        input_signatures=["phone_hash", "email_hash"],
        tech_targets=["IM Backend", "Social Graph"],
        compliance_refs=["个人信息保护法-第17条", "个人信息保护法-第45条"],
        remediation="Use private set intersection (PSI) protocol for contact discovery "
                    "with rate limiting and constant-time responses",
        poc_template="Contact discovery timing side-channel check (harmless)"
    ),
    VerticalRule(
        rule_id="IM-PUSH-LEAK-001",
        industry="instant_messaging",
        name="Push Notification Content Leakage",
        category="SENSITIVE_DATA_EXPOSURE",
        cwe="CWE-200",
        severity="MEDIUM",
        description="Push notifications contain full message text visible on lock screen, "
                    "exposing sensitive content to shoulder surfing",
        detection_pattern="Check push notification payload contains message body "
                         "without content classification",
        sink_signatures=["push_notification", "fcm_payload", "apns_payload"],
        input_signatures=["message_body", "notification_content"],
        tech_targets=["FCM", "APNs", "Push Service"],
        compliance_refs=["个人信息保护法-第51条"],
        remediation="Implement content-based push notification filtering, default to "
                    "'New message' sender-only display with opt-in for previews",
        poc_template="Push payload content inspection (harmless)"
    ),
    VerticalRule(
        rule_id="IM-RECALL-001",
        industry="instant_messaging",
        name="Message Recall Security Gap",
        category="LOGIC_FLAW",
        cwe="CWE-284",
        severity="MEDIUM",
        description="Message recall implementation has timing window where recalled "
                    "content remains accessible via API or notification cache",
        detection_pattern="Check recall API properly deletes from all caches and "
                         "notification systems",
        sink_signatures=["message_recall", "recall_message", "delete_message"],
        input_signatures=["message_id", "recall_token"],
        tech_targets=["IM Server", "Message Store"],
        compliance_refs=["个人信息保护法-第47条"],
        remediation="Implement atomic recall across all notification systems and "
                    "client caches with recall token verification",
        poc_template="Recall API timing test (harmless)"
    ),
    VerticalRule(
        rule_id="IM-BOT-WEBHOOK-001",
        industry="instant_messaging",
        name="Bot Webhook URL Validation Missing",
        category="SSRF",
        cwe="CWE-918",
        severity="HIGH",
        description="Bot platform accepts arbitrary webhook URLs enabling SSRF "
                    "against internal network resources",
        detection_pattern="Check webhook URL is validated against internal IP ranges "
                         "and uses outbound proxy with filtering",
        sink_signatures=["webhook_url", "bot_webhook", "callback_url"],
        input_signatures=["url", "endpoint", "bot_id"],
        tech_targets=["Bot Platform", "IM Bot", "Chatbot"],
        compliance_refs=["GB/T 22239-2019 三级8.1.3"],
        remediation="Validate webhook URLs block internal IP ranges, use signed webhook "
                    "tokens with HMAC verification",
        poc_template="Webhook URL SSRF probe with internal IP (harmless)"
    ),
]


# ============================================================
# IoT RULES (9 rules)
# ============================================================

_IOT_RULES = [
    VerticalRule(
        rule_id="IOT-MQTT-AUTH-001",
        industry="iot",
        name="MQTT Broker Authentication Bypass",
        category="AUTH_BYPASS",
        cwe="CWE-287",
        severity="CRITICAL",
        owasp="A07:2021",
        description="MQTT broker accepts anonymous connections or uses weak "
                    "authentication enabling unauthorized command injection to devices",
        detection_pattern="Check MQTT broker requires TLS client certificates or "
                         "strong credentials",
        sink_signatures=["mqtt_connect", "mqtt_publish", "mosquitto"],
        input_signatures=["client_id", "username", "password", "topic"],
        tech_targets=["MQTT", "MQTT-SN", "Broker", "IoT Device"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4", "GB/T 37044-2018"],
        remediation="Enable mutual TLS for MQTT, implement ACL per client certificate, "
                    "disable anonymous access",
        poc_template="MQTT anonymous connect probe (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-COAP-SEC-001",
        industry="iot",
        name="CoAP DTLS Security Verification",
        category="CRYPTO_FAILURE",
        cwe="CWE-319",
        severity="CRITICAL",
        description="CoAP (Constrained Application Protocol) communication without "
                    "DTLS encryption exposes device control commands",
        detection_pattern="Verify CoAP endpoints require DTLS with PSK or certificate",
        sink_signatures=["coap_handler", "coap_endpoint", "dtls"],
        input_signatures=["coap_uri", "token"],
        tech_targets=["CoAP", "6LoWPAN", "IoT Device", "LwM2M"],
        compliance_refs=["GB/T 37044-2018", "GB/T 22239-2019 三级8.1.3"],
        remediation="Enable mandatory DTLS 1.2+ for all CoAP endpoints, use PSK "
                    "for constrained devices",
        poc_template="CoAP unencrypted traffic probe (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-OTA-SIGN-001",
        industry="iot",
        name="OTA Firmware Update Integrity Protection",
        category="INTEGRITY_FAILURE",
        cwe="CWE-345",
        severity="CRITICAL",
        description="Over-the-air firmware updates without cryptographic signature "
                    "verification allow device takeover via malicious firmware",
        detection_pattern="Verify OTA update pipeline validates firmware signatures "
                         "before applying, with anti-rollback protection",
        sink_signatures=["ota_handler", "firmware_download", "boot_verify"],
        input_signatures=["firmware_url", "version", "signature"],
        tech_targets=["OTA", "Firmware", "Bootloader", "Device"],
        compliance_refs=["GB/T 36627-2018", "GB/T 37044-2018 7.3"],
        remediation="Implement secure boot chain with ECDSA firmware verification, "
                    "anti-rollback monotonic counter, and A/B partition scheme",
        poc_template="Firmware integrity verification check (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-DEVICE-SHADOW-001",
        industry="iot",
        name="Device Shadow/Thing Model Access Control",
        category="BROKEN_ACCESS_CONTROL",
        cwe="CWE-862",
        severity="HIGH",
        description="IoT platform device shadow API lacks tenant isolation, allowing "
                    "cross-tenant device shadow manipulation",
        detection_pattern="Verify device shadow API enforces tenant/project isolation",
        sink_signatures=["device_shadow", "desired_state", "reported_state"],
        input_signatures=["device_id", "tenant_id"],
        tech_targets=["IoT Platform", "Device Shadow", "Digital Twin"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4"],
        remediation="Implement tenant-scoped device shadow access with IAM policies",
        poc_template="Cross-tenant shadow access test (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-SENSOR-INTEGRITY-001",
        industry="iot",
        name="Sensor Data Integrity Verification",
        category="DATA_INTEGRITY",
        cwe="CWE-345",
        severity="HIGH",
        description="IoT sensor data ingestion does not authenticate or sign sensor "
                    "readings, allowing data injection attacks",
        detection_pattern="Check sensor data ingestion verifies HMAC or digital signatures",
        sink_signatures=["sensor_ingest", "telemetry_handler", "data_point"],
        input_signatures=["sensor_id", "reading", "timestamp"],
        tech_targets=["IoT Sensor", "Telemetry", "Edge Gateway"],
        compliance_refs=["GB/T 37044-2018"],
        remediation="Implement HMAC-SHA256 per-device signing of sensor data with "
                    "server-side verification and replay protection",
        poc_template="Sensor data signature verification check (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-EDGE-GATEWAY-001",
        industry="iot",
        name="Edge Computing Gateway API Security",
        category="INSECURE_API",
        cwe="CWE-306",
        severity="HIGH",
        description="Edge computing node exposes management API without authentication, "
                    "enabling local network attackers to compromise deployed models",
        detection_pattern="Verify edge gateway APIs require authentication and "
                         "run with minimal privileges",
        sink_signatures=["edge_api", "model_deploy", "inference_endpoint"],
        input_signatures=["model_config", "deploy_token"],
        tech_targets=["Edge Computing", "MEC", "K3s", "KubeEdge", "Edge AI"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4"],
        remediation="Enable mTLS for all edge management APIs with service mesh "
                    "authorization policies",
        poc_template="Edge API authentication probe (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-ZIGBEE-SEC-001",
        industry="iot",
        name="Zigbee/LoRaWAN Network Key Protection",
        category="CRYPTO_FAILURE",
        cwe="CWE-321",
        severity="HIGH",
        description="Zigbee/LoRaWAN network keys stored in plaintext or derived from "
                    "predictable device attributes, enabling wireless sniffing attacks",
        detection_pattern="Check Zigbee/LoRaWAN key storage uses hardware-backed "
                         "secure element, not plaintext in config files",
        sink_signatures=["zigbee_key", "lorawan_appkey", "network_key"],
        input_signatures=["link_key", "app_key", "dev_eui"],
        tech_targets=["Zigbee", "LoRaWAN", "BLE", "Mesh Network"],
        compliance_refs=["GB/T 37044-2018", "GB/T 22239-2019 三级8.1.3"],
        remediation="Store network keys in device secure element, rotate keys via "
                    "authenticated key exchange protocol",
        poc_template="Key storage inspection (harmless, config only)"
    ),
    VerticalRule(
        rule_id="IOT-DIGITAL-TWIN-001",
        industry="iot",
        name="Digital Twin Synchronization Authorization",
        category="IDOR",
        cwe="CWE-639",
        severity="MEDIUM",
        description="Digital twin API does not verify user ownership of physical device, "
                    "allowing cross-user digital twin access",
        detection_pattern="Verify digital twin API checks device ownership",
        sink_signatures=["twin_api", "twin_update", "shadow_sync"],
        input_signatures=["twin_id", "device_id", "user_id"],
        tech_targets=["Digital Twin", "IoT Platform", "Smart City"],
        compliance_refs=["GB/T 22239-2019 三级8.1.4"],
        remediation="Add device-ownership verification to all twin API operations",
        poc_template="Cross-user twin access test (harmless)"
    ),
    VerticalRule(
        rule_id="IOT-SUPPLY-CHAIN-001",
        industry="iot",
        name="Hardware Supply Chain Provenance Verification",
        category="SUPPLY_CHAIN",
        cwe="CWE-1393",
        severity="MEDIUM",
        description="IoT devices do not verify hardware provenance or component "
                    "identities during boot, allowing counterfeit component substitution",
        detection_pattern="Check device boot sequence verifies hardware attestation "
                         "and component certificates",
        sink_signatures=["hardware_attest", "component_verify", "secure_boot"],
        input_signatures=["device_cert", "hw_id"],
        tech_targets=["IoT Hardware", "Secure Boot", "TPM", "PUF"],
        compliance_refs=["GB/T 36627-2018", "GB/T 37044-2018"],
        remediation="Implement hardware root of trust with per-component attestation "
                    "and immutable device identity",
        poc_template="Hardware attestation check (harmless)"
    ),
]


# ============================================================
# REGISTRY
# ============================================================

VERTICAL_RULES: Dict[str, List[VerticalRule]] = {
    "video_surveillance": _VIDEO_SURVEILLANCE_RULES,
    "instant_messaging": _INSTANT_MESSAGING_RULES,
    "iot": _IOT_RULES,
}


def get_vertical_rules(industry: str) -> VerticalRuleSet:
    """Get all rules for a vertical industry."""
    rules = VERTICAL_RULES.get(industry, [])
    industry_names = {
        "video_surveillance": "Video Surveillance",
        "instant_messaging": "Instant Messaging",
        "iot": "Internet of Things (IoT)",
    }
    return VerticalRuleSet(
        industry=industry,
        rules=rules,
        version="3.1.0",
        description=industry_names.get(industry, industry),
    )


def get_rules_by_industry(industry: str, severity_filter: Optional[str] = None) -> List[VerticalRule]:
    """Get rules for an industry, optionally filtered by severity."""
    rules = VERTICAL_RULES.get(industry, [])
    if severity_filter:
        severity_upper = severity_filter.upper()
        rules = [r for r in rules if r.severity.upper() == severity_upper and r.enabled]
    return [r for r in rules if r.enabled]


def list_vertical_industries() -> List[str]:
    """List all vertical industry keys."""
    return list(VERTICAL_RULES.keys())


def count_vertical_rules(industry: Optional[str] = None) -> int:
    """Count rules, optionally filtered by industry."""
    if industry:
        return len(VERTICAL_RULES.get(industry, []))
    return sum(len(rules) for rules in VERTICAL_RULES.values())
