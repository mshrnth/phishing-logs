#!/usr/bin/env python3
"""
Synthetic Phishing Log Generator for Blue Team, SIEM, and SOAR Training / Testing.
Generates realistic, chronologically consistent, paired SMTP gateway logs (Postfix)
and Mailbox logs (Microsoft 365 / Exchange Online / Defender XDR / Outlook headers)
for pre-user interaction phishing scenarios.
"""

import os
import sys
import json
import uuid
import secrets
import base64
from datetime import datetime, timedelta, timezone

def generate_random_base64(num_bytes=192):
    raw = secrets.token_bytes(num_bytes)
    b64 = base64.b64encode(raw).decode('ascii')
    # Format into lines of 64 chars
    return "\n ".join(b64[i:i+64] for i in range(0, len(b64), 64))

def format_rfc822_date(dt):
    # e.g., Thu, 01 Oct 2026 02:45:06 +0000
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")

def format_iso8601_z(dt):
    # e.g., 2026-10-01T02:45:07.810Z
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def format_iso8601_sec_z(dt):
    # e.g., 2026-10-01T02:45:10Z
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_scenario_data():
    return [
        {
            "id": 1,
            "theme": "Payroll / Direct Deposit Credential Harvesting",
            "base_time": datetime(2026, 10, 1, 2, 45, 6, tzinfo=timezone.utc),
            "attacker_ip": "185.196.220.44",
            "attacker_domain": "payroll-notifications-cloud.net",
            "attacker_host": "mail.payroll-notifications-cloud.net",
            "attacker_rdns_fake": "vps-host-44.bulletrelay.net",
            "sender_name": "Contoso HR & Payroll",
            "sender_email": "notifications@payroll-notifications-cloud.net",
            "reply_to": "Direct Deposit Support <payroll-update@payroll-notifications-cloud.net>",
            "recipient_name": "Jane Doe",
            "recipient_email": "jdoe@contoso.com",
            "recipient_title": "Financial Analyst",
            "subject_clean": "Urgent: Mandatory Verification of Direct Deposit Allocation",
            "subject_tagged": "[EXTERNAL] Urgent: Mandatory Verification of Direct Deposit Allocation",
            "mailer": "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)",
            "mailer_type": "phpmailer",
            "phish_url": "https://contoso-portal-directdeposit.auth-service-verify.com/auth/login?id=jdoe-9921",
            "rule_name": "Allowlist - Third Party HR Systems",
            "rule_id": "4a81bc77-9811-4fa2-bc42-90e8a7192834",
            "bypass_reason": "Sender domain matches 'payroll-*'",
            "scl": -1,
            "sfv": "SKN",
            "threat_cat": "PHSH",
            "gateway_score": "3.9/5.0",
            "body_html_headline": "Contoso Corporate Portal - Action Required",
            "body_html_action": "Review Direct Deposit Profile",
            "ref_ticket": "#DD-202610-88190"
        },
        {
            "id": 2,
            "theme": "Microsoft 365 Password Expiration / AiTM Credential Phish",
            "base_time": datetime(2026, 10, 1, 3, 12, 14, tzinfo=timezone.utc),
            "attacker_ip": "91.240.118.82",
            "attacker_domain": "security-update-tenant365.com",
            "attacker_host": "relay.security-update-tenant365.com",
            "attacker_rdns_fake": "srv-node82.hostnoc-cloud.com",
            "sender_name": "Contoso IT Helpdesk",
            "sender_email": "no-reply@security-update-tenant365.com",
            "reply_to": "IT Identity Operations <helpdesk-identity@security-update-tenant365.com>",
            "recipient_name": "Michael Chen",
            "recipient_email": "mchen@contoso.com",
            "recipient_title": "Senior Systems Engineer",
            "subject_clean": "Immediate Notice: Password Expiration for mchen@contoso.com",
            "subject_tagged": "[EXTERNAL] Immediate Notice: Password Expiration for mchen@contoso.com",
            "mailer": "Roundcube Webmail/1.5.3",
            "mailer_type": "roundcube",
            "phish_url": "https://login.microsoftonline.contoso-auth-verify.com/common/oauth2/v2.0/authorize?user=mchen%40contoso.com",
            "rule_name": "External Sender Warning",
            "rule_id": "c19b4502-3901-4aa2-8710-1845bb094a11",
            "bypass_reason": "Zero-day phishing domain with neutral reputation; bypassed ML classifier",
            "scl": 1,
            "sfv": "NSPM",
            "threat_cat": "NONE",
            "gateway_score": "2.4/5.0",
            "body_html_headline": "Contoso Identity Management - Password Expiry",
            "body_html_action": "Keep Current Password & Re-Authenticate",
            "ref_ticket": "#IT-SEC-202610-3341"
        },
        {
            "id": 3,
            "theme": "Executive Contract / DocuSign Signature Lure",
            "base_time": datetime(2026, 10, 1, 4, 28, 40, tzinfo=timezone.utc),
            "attacker_ip": "194.26.29.114",
            "attacker_domain": "secure-docu-review.org",
            "attacker_host": "mail.secure-docu-review.org",
            "attacker_rdns_fake": "static-29-114.datacenter-ix.net",
            "sender_name": "DocuSign Electronic Signature Service",
            "sender_email": "dse@secure-docu-review.org",
            "reply_to": "Legal Contracts Administrator <contracts@secure-docu-review.org>",
            "recipient_name": "Sarah Jenkins",
            "recipient_email": "sarah.jenkins@contoso.com",
            "recipient_title": "Corporate Counsel",
            "subject_clean": "DocuSign: Please Review & Sign: Contoso Master Services Agreement Q4-2026.pdf",
            "subject_tagged": "[EXTERNAL] DocuSign: Please Review & Sign: Contoso Master Services Agreement Q4-2026.pdf",
            "mailer": "GoPhish Mailer v0.12.1",
            "mailer_type": "gophish",
            "phish_url": "https://docusign-envelope-review.secure-docu-review.org/view/doc?envelope_id=a8291f04-9844-42b1",
            "rule_name": "Vendor Contract Routing Bypass",
            "rule_id": "7820a1bc-89cc-4321-b0a1-77810459c012",
            "bypass_reason": "Subject matches 'DocuSign:*' with high executive priority override",
            "scl": -1,
            "sfv": "SKN",
            "threat_cat": "PHSH",
            "gateway_score": "4.1/5.0",
            "body_html_headline": "DocuSign Document Delivery Notice",
            "body_html_action": "Review & Sign Document",
            "ref_ticket": "#DOCU-ENV-902184-Q4"
        }
    ]

def generate_log_pair(sc, out_dir="."):
    t0 = sc["base_time"]
    t_gw_conn   = t0 + timedelta(seconds=1, milliseconds=810)
    t_gw_rdns   = t0 + timedelta(seconds=1, milliseconds=925)
    t_gw_tls    = t0 + timedelta(seconds=2, milliseconds=12)
    t_gw_queue  = t0 + timedelta(seconds=2, milliseconds=114)
    t_gw_clean  = t0 + timedelta(seconds=2, milliseconds=420)
    t_gw_dkim   = t0 + timedelta(seconds=2, milliseconds=612)
    t_gw_spf    = t0 + timedelta(seconds=2, milliseconds=784)
    t_gw_dmarc  = t0 + timedelta(seconds=2, milliseconds=850)
    t_gw_spam   = t0 + timedelta(seconds=3, milliseconds=32)
    t_gw_qmgr   = t0 + timedelta(seconds=3, milliseconds=210)
    t_gw_relay  = t0 + timedelta(seconds=3, milliseconds=410)
    t_gw_del    = t0 + timedelta(seconds=3, milliseconds=450)
    t_gw_disconn= t0 + timedelta(seconds=3, milliseconds=520)

    t_eop_rec   = t_gw_relay + timedelta(milliseconds=2)
    t_eop_rule1 = t_gw_relay + timedelta(milliseconds=270)
    t_eop_rule2 = t_gw_relay + timedelta(milliseconds=380)
    t_eop_deliv = t_gw_relay + timedelta(milliseconds=680)

    # Identifiers
    hex_id = secrets.token_hex(16)
    queue_id = f"4X{secrets.token_hex(4).upper()}zqz2Vb"
    msg_id = f"<{hex_id}@{sc['attacker_domain']}>"
    net_msg_id = str(uuid.uuid4())
    boundary = f"b1_{hex_id}"
    internal_id = str(secrets.randbelow(900000000000) + 100000000000)
    graph_msg_id = f"AAMkADhkOWM2YTZmLTllYmItNDkyNC1hZGI0LWVhOTg0OTM2OGQ3MQBGAAAAAAB4{secrets.token_hex(18)}..."

    # Common Gateway IPs
    gw_ingress = "198.145.89.25"
    gw_egress = "198.145.89.26"
    eop_ip = "104.47.74.35"
    eop_host = "BN8NAM11FT029.mail.protection.outlook.com"
    tenant_id = "7b81c2f4-610b-419b-a3d8-e1b93d45c802"

    transit_size = 6742 + (sc["id"] * 128)
    delivered_size = transit_size + 382

    # --- BUILD SMTP.TXT / SMTP.LOG CONTENT ---
    smtp_content = f"""# ==============================================================================
# INBOUND SMTP GATEWAY LOGS (mailgw01.contoso.com)
# Scenario {sc['id']}: {sc['theme']} (Pre-User Interaction Stage)
# Gateway Ingress Public IP: {gw_ingress} / Gateway Egress Public IP: {gw_egress}
# Originating Attacker IP: {sc['attacker_ip']} (Attacker VPS, rDNS failed / non-resolving)
# Claimed Sender: "{sc['sender_name']}" <{sc['sender_email']}>
# Target Recipient: {sc['recipient_name']} <{sc['recipient_email']}>
# Relay Target: contoso-com.mail.protection.outlook.com [{eop_ip}]:25
# ==============================================================================

# --- SECTION 1: POSTFIX / MTA SYSTEM & SESSION LOGS (SYSLOG RFC 5424) ---

{format_iso8601_z(t_gw_conn)} mailgw01.contoso.com postfix/smtpd[48210]: connect from unknown[{sc['attacker_ip']}]
{format_iso8601_z(t_gw_rdns)} mailgw01.contoso.com postfix/smtpd[48210]: warning: hostname {sc['attacker_rdns_fake']} does not resolve to address {sc['attacker_ip']}: Name or service not known
{format_iso8601_z(t_gw_tls)} mailgw01.contoso.com postfix/smtpd[48210]: Anonymous TLS connection established from unknown[{sc['attacker_ip']}]: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256
{format_iso8601_z(t_gw_queue)} mailgw01.contoso.com postfix/smtpd[48210]: {queue_id}: client=unknown[{sc['attacker_ip']}]
{format_iso8601_z(t_gw_clean)} mailgw01.contoso.com postfix/cleanup[48215]: {queue_id}: message-id={msg_id}
{format_iso8601_z(t_gw_dkim)} mailgw01.contoso.com opendkim[1104]: {queue_id}: no signature data found for domain {sc['attacker_domain']}
{format_iso8601_z(t_gw_spf)} mailgw01.contoso.com policyd-spf[48218]: prepend Received-SPF: SoftFail (mailgw01.contoso.com: domain of transitioning {sc['sender_email']} does not designate {sc['attacker_ip']} as permitted sender) identity=mailfrom; client-ip={sc['attacker_ip']}; helo={sc['attacker_host']}; envelope-from={sc['sender_email']}; receiver={sc['recipient_email']}
{format_iso8601_z(t_gw_dmarc)} mailgw01.contoso.com dmarc-filter[1180]: {queue_id}: dmarc-result=fail (p=none sp=none pct=100) reason="SPF failed, DKIM missing" domain={sc['attacker_domain']}
{format_iso8601_z(t_gw_spam)} mailgw01.contoso.com mailfilter[48220]: {queue_id}: Antivirus=CLEAN SpamCheck=SUSPICIOUS Score={sc['gateway_score']} RuleHits=HTML_MESSAGE,SUSP_URL_KEYWORD,SPF_SOFTFAIL,NO_DKIM,URGENT_SUBJECT Action=TAG_HEADER
{format_iso8601_z(t_gw_qmgr)} mailgw01.contoso.com postfix/qmgr[2814]: {queue_id}: from=<{sc['sender_email']}>, size={transit_size}, nrcpt=1 (queue active)
{format_iso8601_z(t_gw_relay)} mailgw01.contoso.com postfix/smtp[48225]: {queue_id}: to=<{sc['recipient_email']}>, relay=contoso-com.mail.protection.outlook.com[{eop_ip}]:25, delay=1.6, delays=1.1/0.01/0.12/0.37, dsn=2.6.0, status=sent (250 2.6.0 {msg_id} [InternalId={internal_id}, Hostname=SJ0PR03MB7491.namprd03.prod.outlook.com] {delivered_size} bytes in 0.281s, 24.772 KB/sec Queued mail for delivery)
{format_iso8601_z(t_gw_del)} mailgw01.contoso.com postfix/qmgr[2814]: {queue_id}: removed
{format_iso8601_z(t_gw_disconn)} mailgw01.contoso.com postfix/smtpd[48210]: disconnect from unknown[{sc['attacker_ip']}] ehlo=2 starttls=1 mail=1 rcpt=1 data=1 quit=1 commands=7


# --- SECTION 2: RAW SMTP SESSION CAPTURE (mailgw01 INGRESS INTERFACE) ---

[SESSION ID: {queue_id}]
[PEER: {sc['attacker_ip']}:48214 -> {gw_ingress}:25]
[TIME: {format_iso8601_z(t_gw_conn)}]

S: 220 mailgw01.contoso.com ESMTP Postfix (Ubuntu)
C: EHLO {sc['attacker_host']}
S: 250-mailgw01.contoso.com
S: 250-PIPELINING
S: 250-SIZE 52428800
S: 250-VRFY
S: 250-ETRN
S: 250-STARTTLS
S: 250-ENHANCEDSTATUSCODES
S: 250-8BITMIME
S: 250-DSN
S: 250-SMTPUTF8
S: 250 CHUNKING
C: STARTTLS
S: 220 2.0.0 Ready to start TLS
[--- TLSv1.3 Handshake Completed: TLS_AES_256_GCM_SHA384 ---]
C: EHLO {sc['attacker_host']}
S: 250-mailgw01.contoso.com
S: 250-PIPELINING
S: 250-SIZE 52428800
S: 250-VRFY
S: 250-ETRN
S: 250-ENHANCEDSTATUSCODES
S: 250-8BITMIME
S: 250-DSN
S: 250-SMTPUTF8
S: 250 CHUNKING
C: MAIL FROM:<{sc['sender_email']}>
S: 250 2.1.0 Ok
C: RCPT TO:<{sc['recipient_email']}>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: Received: from {sc['attacker_host']} (localhost [127.0.0.1])
C: 	by {sc['attacker_host']} (Postfix) with ESMTP id 3fa89b12
C: 	for <{sc['recipient_email']}>; {format_rfc822_date(t0)}
C: Date: {format_rfc822_date(t0)}
C: To: <{sc['recipient_email']}>
C: From: "{sc['sender_name']}" <{sc['sender_email']}>
C: Reply-To: {sc['reply_to']}
C: Subject: {sc['subject_clean']}
C: Message-ID: {msg_id}
C: X-Priority: 1
C: X-Mailer: {sc['mailer']}
C: MIME-Version: 1.0
C: Content-Type: multipart/alternative;
C: 	boundary="{boundary}"
C: Content-Transfer-Encoding: 8bit
C: 
C: This is a multi-part message in MIME format.
C: 
C: --{boundary}
C: Content-Type: text/plain; charset=us-ascii
C: 
C: Dear {sc['recipient_name']},
C: 
C: A critical security or account notification was dispatched for your profile on October 1, 2026.
C: 
C: Immediate action is required to maintain system access and verify credentials:
C: {sc['phish_url']}
C: 
C: This link will expire within 24 hours.
C: 
C: Regards,
C: Corporate Support Services
C: 
C: --{boundary}
C: Content-Type: text/html; charset=us-ascii
C: 
C: <!DOCTYPE html>
C: <html>
C: <head><meta charset="utf-8"></head>
C: <body style="font-family: Arial, sans-serif; color: #333;">
C: <table width="600" cellpadding="0" cellspacing="0" style="border: 1px solid #ddd; padding: 20px;">
C: <tr><td>
C: <h2 style="color: #004b87;">{sc['body_html_headline']}</h2>
C: <p>Dear {sc['recipient_name']},</p>
C: <p>A mandatory security action is pending for your account profile: <strong>{sc['recipient_email']}</strong>.</p>
C: <p>Please confirm and authenticate through the secure corporate proxy below:</p>
C: <p style="text-align: center; margin: 30px 0;">
C: <a href="{sc['phish_url']}" style="background-color: #0078d4; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">{sc['body_html_action']}</a>
C: </p>
C: <p><small>Reference Ticket: {sc['ref_ticket']}<br>Security Notice: Contoso Information Security will never ask for your password via plaintext email.</small></p>
C: </td></tr>
C: </table>
C: </body>
C: </html>
C: 
C: --{boundary}--
C: .
S: 250 2.0.0 Ok: queued as {queue_id}
C: QUIT
S: 221 2.0.0 Bye
"""

    # --- BUILD MAILBOX.TXT / MAILBOX.LOG CONTENT ---
    # Antispam header details depending on verdict
    if sc['sfv'] == 'SKN':
        sfv_str = f"SFV:SKN;H:mailgw01.contoso.com;PTR:mailgw01.contoso.com;CAT:{sc['threat_cat']};"
        trace_action = f"Rule '{sc['rule_name']}' matched"
        trace_detail = f"Set spam confidence level (SCL) to {sc['scl']} and bypassed spam filtering (SFV:SKN) due to rule condition: {sc['bypass_reason']}."
        rule_exec_header = f"X-MS-Exchange-Organization-Rules-ExecutionHistory: RuleId:{sc['rule_id']};RuleName:{sc['rule_name']};Action:SetSCL;\n"
        org_policy = "TransportRule"
    else:
        sfv_str = f"SFV:NSPM;H:mailgw01.contoso.com;PTR:mailgw01.contoso.com;CAT:NONE;"
        trace_action = "Spam filter evaluated"
        trace_detail = f"Message classified as Not Spam (SFV:NSPM; SCL:1). Machine learning score passed threshold."
        rule_exec_header = ""
        org_policy = "DefaultSpamPolicy"

    b64_antispam_blob = generate_random_base64(192)

    mailbox_content = f"""# ==============================================================================
# MICROSOFT 365 / EXCHANGE ONLINE & OUTLOOK MAILBOX AUDIT LOGS
# Scenario {sc['id']}: {sc['theme']} (Pre-User Interaction State)
# Target Mailbox: {sc['recipient_email']} ({sc['recipient_name']} - {sc['recipient_title']})
# Mailbox Location: Exchange Online (Tenant ID: {tenant_id})
# Incident Stage: Item Delivered to Inbox; User has NOT read, clicked, or interacted
# Status: Unread (IsRead = False), No URL Click, No Attachment Download
# ==============================================================================


# ------------------------------------------------------------------------------
# SECTION 1: EXCHANGE ONLINE MESSAGE TRACE DETAIL (Get-MessageTraceDetail)
# ------------------------------------------------------------------------------

MessageTraceId        : {net_msg_id}
MessageId             : {msg_id}
Received              : {format_iso8601_z(t_gw_relay)}
SenderAddress         : {sc['sender_email']}
RecipientAddress      : {sc['recipient_email']}
Subject               : {sc['subject_tagged']}
Status                : Delivered
ToIP                  : 10.240.18.62 (Mailbox Database Store)
FromIP                : {gw_egress} (mailgw01.contoso.com Public Egress)
Size                  : {delivered_size}
Direction             : Inbound

Events:
[
  {{
    "Date": "{format_iso8601_z(t_eop_rec)}",
    "Event": "Receive",
    "Action": "Message received by connector {eop_host} from {gw_egress}",
    "Detail": "Inbound session established over TLS 1.3."
  }},
  {{
    "Date": "{format_iso8601_z(t_eop_rule1)}",
    "Event": "Transport rule",
    "Action": "{trace_action}",
    "Detail": "{trace_detail}"
  }},
  {{
    "Date": "{format_iso8601_z(t_eop_rule2)}",
    "Event": "Transport rule",
    "Action": "Rule 'External Sender Warning' matched",
    "Detail": "Prepended '[EXTERNAL] ' to message subject and added external sender metadata header."
  }},
  {{
    "Date": "{format_iso8601_z(t_eop_deliv)}",
    "Event": "Deliver",
    "Action": "Delivered to mailbox",
    "Detail": "The message was successfully delivered to the mailbox '{sc['recipient_email']}' in folder 'Inbox'. InternalMessageId: {internal_id}."
  }}
]


# ------------------------------------------------------------------------------
# SECTION 2: DEFENDER XDR (ADVANCED HUNTING) & PURVIEW AUDIT TELEMETRY
# (KQL query results confirming pre-interaction state at {format_iso8601_z(t_eop_deliv)})
# ------------------------------------------------------------------------------

# Query: EmailEvents | where NetworkMessageId == "{net_msg_id}"
{{
  "Timestamp": "{format_iso8601_z(t_eop_deliv)}",
  "NetworkMessageId": "{net_msg_id}",
  "InternetMessageId": "{msg_id}",
  "SenderMailFromAddress": "{sc['sender_email']}",
  "SenderFromAddress": "{sc['sender_email']}",
  "SenderDisplayName": "{sc['sender_name']}",
  "RecipientEmailAddress": "{sc['recipient_email']}",
  "Subject": "{sc['subject_tagged']}",
  "DeliveryAction": "Delivered",
  "DeliveryLocation": "Inbox",
  "EmailDirection": "Inbound",
  "SenderIPv4": "{sc['attacker_ip']}",
  "AuthenticationDetails": "{{\\"SPF\\": \\"softfail\\", \\"DKIM\\": \\"none\\", \\"DMARC\\": \\"fail\\"}}",
  "ThreatTypes": "Phish",
  "ThreatNames": "URL-Reputation",
  "DetectionMethods": "URL analysis",
  "EmailLanguage": "en",
  "OrgLevelAction": "Allow",
  "OrgLevelPolicy": "{org_policy}",
  "UserLevelAction": "None",
  "UserLevelPolicy": "None"
}}

# Query: UrlClickEvents | where NetworkMessageId == "{net_msg_id}"
# Result: 0 records found. (No SafeLinks click events registered)

# Query: EmailPostDeliveryEvents | where NetworkMessageId == "{net_msg_id}"
# Result: 0 records found. (No ZAP, quarantine release, or user-reported phish events yet)

# Query: Search-UnifiedAuditLog -RecordType ExchangeItem -Operations MailItemsAccessed -FreeText "{net_msg_id}"
# Result: 0 records found. (Mailbox owner {sc['recipient_email']} has NOT opened/read or accessed the item)


# ------------------------------------------------------------------------------
# SECTION 3: OUTLOOK MAPI / GRAPH API MESSAGE OBJECT (INBOX ITEM STATE)
# ------------------------------------------------------------------------------

GET https://graph.microsoft.com/v1.0/users/{sc['recipient_email']}/messages/{graph_msg_id}
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{{
  "id": "{graph_msg_id}",
  "createdDateTime": "{format_iso8601_sec_z(t_eop_deliv)}",
  "lastModifiedDateTime": "{format_iso8601_sec_z(t_eop_deliv)}",
  "receivedDateTime": "{format_iso8601_sec_z(t_eop_deliv)}",
  "sentDateTime": "{format_iso8601_sec_z(t0)}",
  "hasAttachments": false,
  "internetMessageId": "{msg_id}",
  "subject": "{sc['subject_tagged']}",
  "importance": "high",
  "parentFolderId": "AQMkADhkOWM2YTZmLTllYmItNDkyNC1hZGI0LWVhOTg0OTM2OGQ3MQAuAAADeGfT9clnNUmtu...",
  "conversationId": "AAQkADhkOWM2YTZmLTllYmItNDkyNC1hZGI0LWVhOTg0OTM2OGQ3MQAQAMX...",
  "isRead": false,
  "isDraft": false,
  "webLink": "https://outlook.office365.com/owa/?ItemID={graph_msg_id}",
  "inferenceClassification": "other",
  "sender": {{
    "emailAddress": {{
      "name": "{sc['sender_name']}",
      "address": "{sc['sender_email']}"
    }}
  }},
  "from": {{
    "emailAddress": {{
      "name": "{sc['sender_name']}",
      "address": "{sc['sender_email']}"
    }}
  }},
  "toRecipients": [
    {{
      "emailAddress": {{
        "name": "{sc['recipient_name']}",
        "address": "{sc['recipient_email']}"
      }}
    }}
  ],
  "replyTo": [
    {{
      "emailAddress": {{
        "name": "{sc['reply_to'].split('<')[0].strip()}",
        "address": "{sc['reply_to'].split('<')[1].replace('>', '').strip()}"
      }}
    }}
  ],
  "flag": {{
    "flagStatus": "notFlagged"
  }}
}}


# ------------------------------------------------------------------------------
# SECTION 4: COMPLETE RFC 822 / OUTLOOK INTERNET MESSAGE HEADERS
# (Extracted via Outlook Desktop: File -> Properties -> Internet headers,
#  or OWA: Message Details)
# ------------------------------------------------------------------------------

Received: from SJ0PR03MB7491.namprd03.prod.outlook.com (2603:10b6:408:149::19)
 by BL0PR03MB4812.namprd03.prod.outlook.com with HTTPS; {format_rfc822_date(t_eop_deliv)}
Received: from BN0PR03CA0041.namprd03.prod.outlook.com (2603:10b6:408:44::16)
 by SJ0PR03MB7491.namprd03.prod.outlook.com (2603:10b6:408:149::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9123.18; {format_rfc822_date(t_eop_deliv)}
Received: from {eop_host}
 (2603:10b6:408:44:cafe::94) by BN0PR03CA0041.outlook.office365.com
 (2603:10b6:408:44::16) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9123.14 via Frontend
 Transport; {format_rfc822_date(t_eop_deliv)}
Authentication-Results: spf=softfail (sender IP is {sc['attacker_ip']})
 smtp.mailfrom={sc['attacker_domain']}; dkim=none (message not signed)
 header.d=none; dmarc=fail action=none
 header.from={sc['attacker_domain']}; compauth=fail reason=001
Received-SPF: SoftFail (protection.outlook.com: domain of transitioning
 {sc['attacker_domain']} discourages use of {sc['attacker_ip']} as permitted sender)
Received: from mailgw01.contoso.com ({gw_egress}) by
 {eop_host} ({eop_ip}) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9123.11 via
 Frontend Transport; {format_rfc822_date(t_gw_relay)}
X-Gateway-Scanned: mailgw01.contoso.com on {t_gw_spam.strftime('%Y-%m-%d_%H:%M:%S')}
X-Gateway-Spam-Status: No, score={sc['gateway_score'].split('/')[0]} required=5.0 tests=HTML_MESSAGE,SPF_SOFTFAIL,NO_DKIM,URGENT_SUBJECT,SUSP_URL_KEYWORD autolearn=no
X-Gateway-Spam-Score: {sc['gateway_score'].split('/')[0]}
Received-SPF: SoftFail (mailgw01.contoso.com: domain of transitioning
 {sc['sender_email']} does not designate {sc['attacker_ip']} as
 permitted sender) identity=mailfrom; client-ip={sc['attacker_ip']};
 helo={sc['attacker_host']};
 envelope-from={sc['sender_email']}; receiver={sc['recipient_email']}
Received: from {sc['attacker_host']} (unknown [{sc['attacker_ip']}])
 by mailgw01.contoso.com (Postfix) with ESMTPS id {queue_id}
 for <{sc['recipient_email']}>; {format_rfc822_date(t_gw_conn)}
Received: from {sc['attacker_host']} (localhost [127.0.0.1])
	by {sc['attacker_host']} (Postfix) with ESMTP id 3fa89b12
	for <{sc['recipient_email']}>; {format_rfc822_date(t0)}
Date: {format_rfc822_date(t0)}
To: <{sc['recipient_email']}>
From: "{sc['sender_name']}" <{sc['sender_email']}>
Reply-To: {sc['reply_to']}
Subject: {sc['subject_tagged']}
Message-ID: {msg_id}
X-Priority: 1
X-Mailer: {sc['mailer']}
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="{boundary}"
Content-Transfer-Encoding: 8bit
Importance: High
X-MSMail-Priority: High
X-External-Sender: YES
X-EOPAttributedMessage: 0
X-MS-Exchange-Organization-MessageDirectionality: Inbound
X-MS-Exchange-Organization-AuthSource: mailgw01.contoso.com
X-MS-Exchange-Organization-AuthAs: Anonymous
X-MS-Exchange-Organization-Network-Message-Id: {net_msg_id}
{rule_exec_header}X-MS-Exchange-Organization-SCL: {sc['scl']}
X-MS-Exchange-Organization-PCL: 2
X-Forefront-Antispam-Report: CIP:{gw_egress};CTRY:US;LANG:en;SCL:{sc['scl']};SRV:DIR;IPV:CAL;{sfv_str}SFS:(136003)(396003)(366004)(346002)(376002);DIR:INB;
X-Microsoft-Antispam: BCL:0;ARA:13230040|46104249079|82310400026|36860700013|440099029;
X-MS-Exchange-CrossTenant-OriginalArrivalTime: {t_gw_relay.strftime('%d %b %Y %H:%M:%S.4100')} (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Internet
X-MS-Exchange-CrossTenant-Id: {tenant_id}
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-EndToEndLatency: 00:00:00.6800000
X-MS-Exchange-Processed-By-BccFoldering: 15.20.9123.018
X-Microsoft-Antispam-Mailbox-Delivery:
 ucf:0;jmr:0;auth:0;dest:I;ENG:(910001)(944506478)(944626604)(920097)(930097)(140003);
X-Microsoft-Antispam-Message-Info:
 {b64_antispam_blob}

This is a multi-part message in MIME format.

--{boundary}
Content-Type: text/plain; charset=us-ascii

Dear {sc['recipient_name']},

A critical security or account notification was dispatched for your profile on October 1, 2026.

Immediate action is required to maintain system access and verify credentials:
{sc['phish_url']}

This link will expire within 24 hours.

Regards,
Corporate Support Services

--{boundary}
Content-Type: text/html; charset=us-ascii

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #333;">
<table width="600" cellpadding="0" cellspacing="0" style="border: 1px solid #ddd; padding: 20px;">
<tr><td>
<h2 style="color: #004b87;">{sc['body_html_headline']}</h2>
<p>Dear {sc['recipient_name']},</p>
<p>A mandatory security action is pending for your account profile: <strong>{sc['recipient_email']}</strong>.</p>
<p>Please confirm and authenticate through the secure corporate proxy below:</p>
<p style="text-align: center; margin: 30px 0;">
<a href="{sc['phish_url']}" style="background-color: #0078d4; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">{sc['body_html_action']}</a>
</p>
<p><small>Reference Ticket: {sc['ref_ticket']}<br>Security Notice: Contoso Information Security will never ask for your password via plaintext email.</small></p>
</td></tr>
</table>
</body>
</html>

--{boundary}--
"""

    smtp_file = os.path.join(out_dir, f"SMTP_{sc['id']}.log")
    mailbox_file = os.path.join(out_dir, f"Mailbox_{sc['id']}.log")

    with open(smtp_file, "w", encoding="utf-8") as f:
        f.write(smtp_content.strip() + "\n")

    with open(mailbox_file, "w", encoding="utf-8") as f:
        f.write(mailbox_content.strip() + "\n")

    return smtp_file, mailbox_file

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(script_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    scenarios = generate_scenario_data()

    print(f"[*] Generating {len(scenarios)} distinct pairs of synthetic phishing logs in '{logs_dir}'...")
    for sc in scenarios:
        s_file, m_file = generate_log_pair(sc, logs_dir)
        print(f"  [+] Scenario {sc['id']} ({sc['theme']}):")
        print(f"      -> SMTP:    {os.path.basename(s_file)} ({os.path.getsize(s_file):,} bytes)")
        print(f"      -> Mailbox: {os.path.basename(m_file)} ({os.path.getsize(m_file):,} bytes)")

    print("[*] Completed successfully! All logs created in 'logs/' directory.")

if __name__ == "__main__":
    main()
