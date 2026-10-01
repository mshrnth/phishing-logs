#!/usr/bin/env python3
"""
Synthetic Phishing & Benign Log Generator for Blue Team, SIEM, and SOAR.
Generates realistic, chronologically consistent, multi-source log datasets:
  - emails/*.eml         : RFC 822 / MIME emails ready for Outlook / EML analysis
  - smtp/*.log           : Individual SMTP logs & protocol session captures for each email

Includes both Phishing and Benign traffic to accurately measure False Positives.
Fully reproducible using a fixed random seed.
"""

import os
import sys
import json
import uuid
import random
import base64
from datetime import datetime, timedelta, timezone

DEFAULT_COUNT = 8
DEFAULT_SEED = 42

TENANT_ID = "7b81c2f4-610b-419b-a3d8-e1b93d45c802"
GW_HOSTNAME = "mailgw01.contoso.com"
GW_INGRESS_IP = "198.145.89.25"
GW_EGRESS_IP = "198.145.89.26"
EOP_HOST = "BN8NAM11FT029.mail.protection.outlook.com"
EOP_IP = "104.47.74.35"
MAILBOX_STORE_IP = "10.240.18.62"

EMPLOYEE_POOL = [
    {"name": "Jane Doe", "email": "jdoe@contoso.com", "title": "Financial Analyst", "dept": "Finance"},
    {"name": "Michael Chen", "email": "mchen@contoso.com", "title": "Senior Systems Engineer", "dept": "IT Operations"},
    {"name": "Sarah Jenkins", "email": "sarah.jenkins@contoso.com", "title": "Corporate Counsel", "dept": "Legal"},
    {"name": "David Ross", "email": "dross@contoso.com", "title": "VP of Global Sales", "dept": "Sales"},
    {"name": "Emily Watson", "email": "ewatson@contoso.com", "title": "Corporate Controller", "dept": "Finance"},
    {"name": "Robert Taylor", "email": "rtaylor@contoso.com", "title": "DevOps Architect", "dept": "Engineering"},
    {"name": "Lisa Wong", "email": "lwong@contoso.com", "title": "Accounts Payable Lead", "dept": "Accounting"},
    {"name": "James Miller", "email": "jmiller@contoso.com", "title": "Director of Operations", "dept": "Operations"},
    {"name": "Karen Martinez", "email": "kmartinez@contoso.com", "title": "HR Business Partner", "dept": "Human Resources"},
    {"name": "Alex Novak", "email": "anovak@contoso.com", "title": "Product Marketing Manager", "dept": "Marketing"},
    {"name": "Brian Patel", "email": "bpatel@contoso.com", "title": "Infrastructure Engineer", "dept": "IT"},
    {"name": "Rachel Adams", "email": "radams@contoso.com", "title": "Chief Information Officer", "dept": "Executive"}
]

SCENARIO_PROFILES = [
    {
        "is_phish": True,
        "theme": "Payroll / Direct Deposit Credential Harvesting",
        "lure_category": "Direct Deposit Modification",
        "mailer_type": "phpmailer",
        "mailer_str": "PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)",
        "attacker_domain": "payroll-notifications-cloud.net",
        "attacker_host": "mail.payroll-notifications-cloud.net",
        "attacker_rdns_fake": "vps-host-44.bulletrelay.net",
        "attacker_ip": "185.196.220.44",
        "sender_name": "Contoso HR & Payroll",
        "sender_email": "notifications@payroll-notifications-cloud.net",
        "reply_to": "Direct Deposit Support <payroll-update@payroll-notifications-cloud.net>",
        "subject_clean": "Urgent: Mandatory Verification of Direct Deposit Allocation",
        "subject_prefix": "[EXTERNAL] ",
        "priority_high": True,
        "auth_results": {
            "spf": "softfail",
            "dkim": "none",
            "dmarc": "fail action=none",
            "compauth": "fail reason=001"
        },
        "sfv": "SKN",
        "scl": -1,
        "threat_cat": "PHSH",
        "bypass_rule_name": "Allowlist - Third Party HR Systems",
        "bypass_rule_id": "4a81bc77-9811-4fa2-bc42-90e8a7192834",
        "bypass_reason": "Sender domain matches 'payroll-*'",
        "gateway_score": 3.9,
        "phish_url": "https://contoso-portal-directdeposit.auth-service-verify.com/auth/login?id={target_alias}-9921",
        "plain_body": (
            "Dear {target_name},\n\n"
            "A change request was submitted for your Contoso Direct Deposit payment instructions on October 1, 2026.\n\n"
            "If you did not authorize this modification, please review and verify your banking profile immediately by visiting:\n"
            "{phish_url}\n\n"
            "This link will expire within 24 hours.\n\n"
            "Regards,\nContoso HR & Compensation Services\n"
        ),
        "html_headline": "Contoso Corporate Portal - Action Required",
        "html_action_btn": "Review Direct Deposit Profile",
        "html_desc": (
            "A change request was submitted for your <strong>Direct Deposit Payment Account</strong> on October 1, 2026.<br>"
            "If this was not requested by you, please review and reject the pending changes immediately to prevent misrouted disbursement."
        ),
        "ref_ticket": "#DD-202610-88190"
    },
    {
        "is_phish": True,
        "theme": "Microsoft 365 Password Expiration / AiTM Credential Phish",
        "lure_category": "IT Identity / Credential Harvesting",
        "mailer_type": "roundcube",
        "mailer_str": "Roundcube Webmail/1.5.3",
        "attacker_domain": "security-update-tenant365.com",
        "attacker_host": "relay.security-update-tenant365.com",
        "attacker_rdns_fake": "srv-node82.hostnoc-cloud.com",
        "attacker_ip": "91.240.118.82",
        "sender_name": "Contoso IT Helpdesk",
        "sender_email": "no-reply@security-update-tenant365.com",
        "reply_to": "IT Identity Operations <helpdesk-identity@security-update-tenant365.com>",
        "subject_clean": "Immediate Notice: Password Expiration for {target_email}",
        "subject_prefix": "[EXTERNAL] ",
        "priority_high": True,
        "auth_results": {
            "spf": "softfail",
            "dkim": "none",
            "dmarc": "fail action=none",
            "compauth": "fail reason=001"
        },
        "sfv": "NSPM",
        "scl": 1,
        "threat_cat": "NONE",
        "bypass_rule_name": None,
        "bypass_rule_id": None,
        "bypass_reason": "Zero-day domain bypassed ML filter; classified as Not Spam at delivery",
        "gateway_score": 2.4,
        "phish_url": "https://login.microsoftonline.contoso-auth-verify.com/common/oauth2/v2.0/authorize?user={target_email}",
        "plain_body": (
            "Notice: Your Contoso corporate password will expire in 6 hours.\n\n"
            "To retain your existing password and prevent account suspension, complete identity re-authentication at:\n"
            "{phish_url}\n\n"
            "Contoso Security Operations Center\n"
        ),
        "html_headline": "Contoso Identity Management - Password Expiry",
        "html_action_btn": "Keep Current Password & Re-Authenticate",
        "html_desc": (
            "Your Contoso domain password for <strong>{target_email}</strong> is scheduled to expire today.<br>"
            "To maintain uninterrupted access to Microsoft 365, Teams, and VPN services, verify your identity now."
        ),
        "ref_ticket": "#IT-SEC-202610-3341"
    },
    {
        "is_phish": True,
        "theme": "Executive Contract / DocuSign Signature Lure",
        "lure_category": "Contract Electronic Signature",
        "mailer_type": "gophish",
        "mailer_str": "GoPhish Mailer v0.12.1",
        "attacker_domain": "secure-docu-review.org",
        "attacker_host": "mail.secure-docu-review.org",
        "attacker_rdns_fake": "static-29-114.datacenter-ix.net",
        "attacker_ip": "194.26.29.114",
        "sender_name": "DocuSign Electronic Signature Service",
        "sender_email": "dse@secure-docu-review.org",
        "reply_to": "Legal Contracts Administrator <contracts@secure-docu-review.org>",
        "subject_clean": "DocuSign: Please Review & Sign: Contoso Master Services Agreement Q4-2026.pdf",
        "subject_prefix": "[EXTERNAL] ",
        "priority_high": True,
        "auth_results": {
            "spf": "softfail",
            "dkim": "none",
            "dmarc": "fail action=none",
            "compauth": "fail reason=001"
        },
        "sfv": "SKN",
        "scl": -1,
        "threat_cat": "PHSH",
        "bypass_rule_name": "Vendor Contract Routing Bypass",
        "bypass_rule_id": "7820a1bc-89cc-4321-b0a1-77810459c012",
        "bypass_reason": "Subject matches 'DocuSign:*' with executive priority override",
        "gateway_score": 4.1,
        "phish_url": "https://docusign-envelope-review.secure-docu-review.org/view/doc?envelope_id=a8291f04-9844-42b1",
        "plain_body": (
            "DocuSign Notification:\n\n"
            "Please review and electronically execute the pending document: Contoso Master Services Agreement Q4-2026.pdf\n\n"
            "Access Document:\n"
            "{phish_url}\n\n"
            "Envelope ID: A8291F04-9844-42B1-B109-8819024C\n"
        ),
        "html_headline": "DocuSign Document Delivery Notice",
        "html_action_btn": "Review & Sign Document",
        "html_desc": (
            "You have received a new document requiring your electronic signature: <strong>Contoso Master Services Agreement Q4-2026.pdf</strong>.<br>"
            "Please review the contractual clauses and sign using your DocuSign corporate profile."
        ),
        "ref_ticket": "#DOCU-ENV-902184-Q4"
    },
    {
        "is_phish": True,
        "theme": "Teams / PBX Cloud Voicemail Notification Lure",
        "lure_category": "Voice Audio Message",
        "mailer_type": "postfix_py",
        "mailer_str": "Postfix with Python-smtplib",
        "attacker_domain": "cloud-voicemail-portal.com",
        "attacker_host": "pbx01.cloud-voicemail-portal.com",
        "attacker_rdns_fake": "vps-node191.telecom-cloud.net",
        "attacker_ip": "193.106.191.22",
        "sender_name": "Microsoft Teams Voicemail Service",
        "sender_email": "noreply-voicemail@cloud-voicemail-portal.com",
        "reply_to": "Unified Messaging Support <support@cloud-voicemail-portal.com>",
        "subject_clean": "New Audio Voicemail from +1 (415) 890-4412 (1m 18s) - Listen Online",
        "subject_prefix": "[EXTERNAL] ",
        "priority_high": False,
        "auth_results": {
            "spf": "softfail",
            "dkim": "none",
            "dmarc": "fail action=none",
            "compauth": "fail reason=001"
        },
        "sfv": "NSPM",
        "scl": 1,
        "threat_cat": "NONE",
        "bypass_rule_name": None,
        "bypass_rule_id": None,
        "bypass_reason": "Zero-day audio notification template evaded heuristics",
        "gateway_score": 2.8,
        "phish_url": "https://teams-cloud-voicemail-player.cloud-voicemail-portal.com/listen?caller=external-4412&token=99281a",
        "plain_body": (
            "You received a new voicemail audio message.\n\n"
            "Caller: +1 (415) 890-4412\n"
            "Duration: 01:18\n"
            "Received: October 1, 2026\n\n"
            "Play audio recording online:\n"
            "{phish_url}\n"
        ),
        "html_headline": "Microsoft Teams Unified Messaging - New Audio Message",
        "html_action_btn": "Play Voicemail Recording (01:18)",
        "html_desc": (
            "A caller left a voice message for your extension: <strong>+1 (415) 890-4412</strong>.<br>"
            "Audio file transcriber: <em>'Hi, this is regarding the quarterly invoice adjustment, please call me back or check...'</em>"
        ),
        "ref_ticket": "#VM-AUDIO-202610-7721"
    },
    {
        "is_phish": True,
        "theme": "SharePoint / OneDrive Encrypted Financial Spreadsheet Share",
        "lure_category": "Financial Document Sharing",
        "mailer_type": "phpmailer",
        "mailer_str": "PHPMailer 6.8.1 (https://github.com/PHPMailer/PHPMailer)",
        "attacker_domain": "sharepoint-docs-vault.net",
        "attacker_host": "cloudrelay.sharepoint-docs-vault.net",
        "attacker_rdns_fake": "cust-node214.dedicated-pool.org",
        "attacker_ip": "45.142.214.77",
        "sender_name": "Contoso Internal Document Sharing",
        "sender_email": "sharepoint-admin@sharepoint-docs-vault.net",
        "reply_to": "Corporate File Operations <fileshare@sharepoint-docs-vault.net>",
        "subject_clean": "Shared Document: \"Contoso_Q3_Bonus_Allocations_Confidential.xlsx\"",
        "subject_prefix": "[EXTERNAL] ",
        "priority_high": True,
        "auth_results": {
            "spf": "softfail",
            "dkim": "none",
            "dmarc": "fail action=none",
            "compauth": "fail reason=001"
        },
        "sfv": "SKN",
        "scl": -1,
        "threat_cat": "PHSH",
        "bypass_rule_name": "Allowlist - Executive Shared Repositories",
        "bypass_rule_id": "89b7201c-33aa-4488-b710-aa9182736450",
        "bypass_reason": "Rule 'Allowlist - Executive Shared Repositories' set SCL to -1",
        "gateway_score": 3.7,
        "phish_url": "https://contoso-sharepoint-docs.sharepoint-docs-vault.net/view?doc=bonus_alloc_q3&auth={target_alias}",
        "plain_body": (
            "SharePoint Online Notification:\n\n"
            "Contoso Internal Document Sharing shared a file with you:\n"
            "\"Contoso_Q3_Bonus_Allocations_Confidential.xlsx\"\n\n"
            "Open file in browser:\n"
            "{phish_url}\n"
        ),
        "html_headline": "SharePoint Online - Encrypted Spreadsheet Shared",
        "html_action_btn": "Open Document in Excel Online",
        "html_desc": (
            "A confidential spreadsheet was shared with you: <strong>Contoso_Q3_Bonus_Allocations_Confidential.xlsx</strong>.<br>"
            "This link requires single sign-on verification to open."
        ),
        "ref_ticket": "#SP-SHARE-202610-4491"
    },
    {
        "is_phish": False,
        "theme": "Internal Corporate Wellness Program Announcement",
        "lure_category": "Internal HR Communication",
        "mailer_type": "exchange_internal",
        "mailer_str": "Microsoft Exchange Server 2019 (15.2.9123.18)",
        "attacker_domain": "contoso.com",
        "attacker_host": "mailgw01.contoso.com",
        "attacker_rdns_fake": "mailgw01.contoso.com",
        "attacker_ip": "10.0.10.50",
        "sender_name": "Contoso HR Communications",
        "sender_email": "hr-announcements@contoso.com",
        "reply_to": "Employee Benefits Team <benefits@contoso.com>",
        "subject_clean": "Contoso Wellness Program: Annual On-Site Flu Shot Clinic",
        "subject_prefix": "",
        "priority_high": False,
        "auth_results": {
            "spf": "pass",
            "dkim": "pass (signature verified)",
            "dmarc": "pass (p=reject)",
            "compauth": "pass reason=100"
        },
        "sfv": "NSPM",
        "scl": -1,
        "threat_cat": "NONE",
        "bypass_rule_name": None,
        "bypass_rule_id": None,
        "bypass_reason": "Internal corporate message; authenticated sender",
        "gateway_score": 0.0,
        "phish_url": "https://intranet.contoso.com/benefits/flu-shots-2026",
        "plain_body": (
            "Hello Contoso Team,\n\n"
            "Our annual on-site seasonal wellness clinic will take place October 15-17 in the building 4 auditorium.\n"
            "Sign up for a timeslot on the intranet:\n"
            "{phish_url}\n\n"
            "Stay healthy!\nContoso People Operations\n"
        ),
        "html_headline": "Contoso Wellness - Annual Seasonal Health Clinic",
        "html_action_btn": "Book Clinic Appointment",
        "html_desc": (
            "People Operations is pleased to offer on-site seasonal vaccinations and wellness screenings.<br>"
            "Appointments are available Monday through Wednesday from 09:00 to 16:30 in Building 4."
        ),
        "ref_ticket": "#HR-WELL-202610-1102"
    },
    {
        "is_phish": False,
        "theme": "Legitimate Vendor Invoice: Amazon Web Services",
        "lure_category": "Vendor Billing Notification",
        "mailer_type": "amazon_ses",
        "mailer_str": "Amazon SES mailer 2.1",
        "attacker_domain": "amazon.com",
        "attacker_host": "a27-14.smtp-out.amazonses.com",
        "attacker_rdns_fake": "a27-14.smtp-out.amazonses.com",
        "attacker_ip": "54.240.27.14",
        "sender_name": "Amazon Web Services",
        "sender_email": "no-reply-aws@amazon.com",
        "reply_to": "AWS Billing Support <aws-billing@amazon.com>",
        "subject_clean": "Amazon Web Services Monthly Invoice #99812401 - Contoso Production Account",
        "subject_prefix": "[EXTERNAL] ",
        "priority_high": False,
        "auth_results": {
            "spf": "pass (sender IP is 54.240.27.14)",
            "dkim": "pass (signature verified d=amazon.com)",
            "dmarc": "pass (p=reject action=none header.from=amazon.com)",
            "compauth": "pass reason=100"
        },
        "sfv": "NSPM",
        "scl": 1,
        "threat_cat": "NONE",
        "bypass_rule_name": None,
        "bypass_rule_id": None,
        "bypass_reason": "Legitimate external vendor with valid SPF, DKIM, and DMARC alignment",
        "gateway_score": 0.2,
        "phish_url": "https://console.aws.amazon.com/billing/home?#/bills?invoiceId=99812401",
        "plain_body": (
            "Amazon Web Services Invoice Summary:\n\n"
            "Account: Contoso Production (9928-1092-4412)\n"
            "Invoice: #99812401\n"
            "Billing Period: September 1, 2026 - September 30, 2026\n"
            "Amount Due: $14,281.40 USD\n\n"
            "View full statement in the AWS Billing Console:\n"
            "{phish_url}\n"
        ),
        "html_headline": "Amazon Web Services - Invoice Available",
        "html_action_btn": "View Invoice Details",
        "html_desc": (
            "Your monthly statement for <strong>Contoso Production Account (9928-1092-4412)</strong> is now ready.<br>"
            "Automatic payment will be processed according to your payment method on file."
        ),
        "ref_ticket": "#AWS-INV-202610-9981"
    },
    {
        "is_phish": False,
        "theme": "Internal IT Maintenance Notice: Weekend VPN Gateway Upgrade",
        "lure_category": "Internal IT Maintenance",
        "mailer_type": "exchange_internal",
        "mailer_str": "Microsoft Exchange Server 2019 (15.2.9123.18)",
        "attacker_domain": "contoso.com",
        "attacker_host": "mailgw01.contoso.com",
        "attacker_rdns_fake": "mailgw01.contoso.com",
        "attacker_ip": "10.0.10.51",
        "sender_name": "Contoso IT Infrastructure Operations",
        "sender_email": "it-ops@contoso.com",
        "reply_to": "IT Helpdesk <helpdesk@contoso.com>",
        "subject_clean": "Scheduled Network Maintenance: Corporate VPN Gateway Upgrade on Saturday",
        "subject_prefix": "",
        "priority_high": False,
        "auth_results": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "compauth": "pass reason=100"
        },
        "sfv": "NSPM",
        "scl": -1,
        "threat_cat": "NONE",
        "bypass_rule_name": None,
        "bypass_rule_id": None,
        "bypass_reason": "Internal corporate operational bulletin",
        "gateway_score": 0.0,
        "phish_url": "https://intranet.contoso.com/it/maintenance-schedule",
        "plain_body": (
            "IT Maintenance Window Announcement:\n\n"
            "The corporate VPN gateways will undergo firmware upgrades this Saturday from 02:00 to 04:00 UTC.\n"
            "Remote access may be temporarily interrupted during this window.\n\n"
            "Full details and service status:\n"
            "{phish_url}\n"
        ),
        "html_headline": "Contoso IT Operations - Infrastructure Notice",
        "html_action_btn": "Check Maintenance Schedule",
        "html_desc": (
            "Scheduled network maintenance is planned for the primary VPN gateway clusters on Saturday.<br>"
            "If you experience connection drops, please wait until the maintenance window completes."
        ),
        "ref_ticket": "#IT-MAINT-202610-5510"
    }
]


def build_scenarios(count, seed=DEFAULT_SEED):
    rng = random.Random(seed)
    scenarios = []

    base_time = datetime(2026, 10, 1, 2, 45, 0, tzinfo=timezone.utc)

    for i in range(count):
        profile_idx = i % len(SCENARIO_PROFILES)
        p = SCENARIO_PROFILES[profile_idx]
        sc = dict(p)
        sc["index"] = i + 1

        emp = EMPLOYEE_POOL[i % len(EMPLOYEE_POOL)]
        sc["recipient_name"] = emp["name"]
        sc["recipient_email"] = emp["email"]
        sc["recipient_title"] = emp["title"]
        sc["recipient_dept"] = emp["dept"]

        target_alias = emp["email"].split('@')[0]

        if i >= len(SCENARIO_PROFILES):
            cycle = i // len(SCENARIO_PROFILES)
            if sc["is_phish"]:
                sc["attacker_domain"] = f"srv{cycle}-{p['attacker_domain']}"
                sc["attacker_host"] = f"mail{cycle}.{sc['attacker_domain']}"
                ip_octets = p["attacker_ip"].split('.')
                ip_octets[-1] = str((int(ip_octets[-1]) + cycle * 11) % 250 + 2)
                sc["attacker_ip"] = ".".join(ip_octets)
                sc["sender_email"] = f"notifications@{sc['attacker_domain']}"
                sc["reply_to"] = f"Support <help@{sc['attacker_domain']}>"

        sc["subject_raw"] = sc["subject_clean"].format(target_email=emp["email"])
        sc["subject_delivered"] = sc["subject_prefix"] + sc["subject_raw"]

        sc["resolved_url"] = sc["phish_url"].format(target_alias=target_alias, target_email=emp["email"])
        sc["resolved_plain_body"] = sc["plain_body"].format(
            target_name=emp["name"],
            target_email=emp["email"],
            phish_url=sc["resolved_url"]
        )
        sc["resolved_html_desc"] = sc["html_desc"].format(
            target_name=emp["name"],
            target_email=emp["email"]
        )

        sc["attacker_queue_id"] = f"{rng.randint(0x10000000, 0xFFFFFFFF):X}"
        sc["hex_token"] = f"{rng.getrandbits(128):032x}"
        sc["queue_id"] = f"4X{rng.getrandbits(32):08X}zqz2Vb"
        sc["message_id"] = f"<{sc['hex_token']}@{sc['attacker_domain']}>"
        sc["network_message_id"] = str(uuid.UUID(int=rng.getrandbits(128)))
        sc["internal_id"] = str(rng.randint(100000000000, 999999999999))
        sc["graph_msg_id"] = f"AAMkADhkOWM2YTZmLTllYmItNDkyNC1hZGI0LWVhOTg0OTM2OGQ3MQBGAAAAAAB4{rng.getrandbits(96):024x}..."

        if sc["mailer_type"] == "phpmailer":
            sc["boundary"] = f"b1_{sc['hex_token']}"
        elif sc["mailer_type"] == "roundcube":
            sc["boundary"] = f"_=_swift_1727750{i}_{sc['hex_token'][:16]}_=_"
        elif sc["mailer_type"] == "gophish":
            sc["boundary"] = f"----=_Part_{rng.randint(1000, 9999)}_{sc['hex_token'][:12]}"
        else:
            sc["boundary"] = f"------------{sc['hex_token'][:24]}"

        body_len = len(sc["resolved_plain_body"]) + len(sc["resolved_html_desc"]) + 1400
        sc["transit_size"] = 5200 + body_len + (i * 47 % 500)
        sc["delivered_size"] = sc["transit_size"] + 382

        d_setup = round(1.0 + (rng.randint(5, 25) / 100.0), 2)
        d_queue = 0.01
        d_conn  = round(0.10 + (rng.randint(1, 5) / 100.0), 2)
        d_xfer  = 0.281
        sc["delay_total"] = round(d_setup + d_queue + d_conn + d_xfer, 1)
        sc["delays_str"] = f"{d_setup:.1f}/{d_queue:.2f}/{d_conn:.2f}/{d_xfer:.2f}"
        sc["transfer_kbps"] = round((sc["delivered_size"] / 1024.0) / d_xfer, 3)

        raw_token = bytes([rng.randint(0, 255) for _ in range(180)])
        b64_str = base64.b64encode(raw_token).decode('ascii')
        sc["antispam_b64"] = "\n ".join(b64_str[j:j+64] for j in range(0, len(b64_str), 64))

        delta_min = (i * 38) + rng.randint(2, 9)
        delta_sec = rng.randint(5, 45)
        t_send = base_time + timedelta(minutes=delta_min, seconds=delta_sec)

        sc["t_send"]    = t_send
        sc["t_conn"]    = t_send + timedelta(seconds=1, milliseconds=100)
        sc["t_rdns"]    = t_send + timedelta(seconds=1, milliseconds=225)
        sc["t_tls"]     = t_send + timedelta(seconds=1, milliseconds=412)
        sc["t_spf"]     = t_send + timedelta(seconds=1, milliseconds=784)
        sc["t_dkim"]    = t_send + timedelta(seconds=1, milliseconds=850)
        sc["t_dmarc"]   = t_send + timedelta(seconds=1, milliseconds=920)
        sc["t_queue"]   = t_send + timedelta(seconds=2, milliseconds=114)
        sc["t_clean"]   = t_send + timedelta(seconds=2, milliseconds=420)
        sc["t_spam"]    = t_send + timedelta(seconds=2, milliseconds=680)
        sc["t_qmgr"]    = t_send + timedelta(seconds=2, milliseconds=850)
        sc["t_relay"]   = sc["t_queue"] + timedelta(seconds=sc["delay_total"])
        sc["t_del"]     = sc["t_relay"] + timedelta(milliseconds=40)
        sc["t_disconn"] = sc["t_relay"] + timedelta(milliseconds=110)
        sc["t_eop_rec"] = sc["t_relay"] + timedelta(milliseconds=2)
        sc["t_eop_rule1"] = sc["t_relay"] + timedelta(milliseconds=270)
        sc["t_eop_rule2"] = sc["t_relay"] + timedelta(milliseconds=380)
        sc["t_eop_deliv"] = sc["t_relay"] + timedelta(milliseconds=680)

        scenarios.append(sc)

    return scenarios


def generate_eml(sc):
    if sc["is_phish"]:
        gw_recv = f"Received: from {sc['attacker_host']} (unknown [{sc['attacker_ip']}])\n by {GW_HOSTNAME} (Postfix) with ESMTPS id {sc['queue_id']}\n for <{sc['recipient_email']}>; {sc['t_conn'].strftime('%a, %d %b %Y %H:%M:%S +0000')}"
    else:
        gw_recv = f"Received: from {sc['attacker_host']} ({sc['attacker_host']} [{sc['attacker_ip']}])\n by {GW_HOSTNAME} (Postfix) with ESMTP id {sc['queue_id']}\n for <{sc['recipient_email']}>; {sc['t_conn'].strftime('%a, %d %b %Y %H:%M:%S +0000')}"

    priority_headers = ""
    if sc["priority_high"]:
        priority_headers = "X-Priority: 1\nPriority: Urgent\nImportance: High\nX-MSMail-Priority: High\n"

    if sc["is_phish"]:
        gw_spf = (
            f"Received-SPF: SoftFail ({GW_HOSTNAME}: domain of transitioning\n"
            f" {sc['sender_email']} does not designate {sc['attacker_ip']} as\n"
            f" permitted sender) identity=mailfrom; client-ip={sc['attacker_ip']};\n"
            f" helo={sc['attacker_host']};\n"
            f" envelope-from={sc['sender_email']}; receiver={sc['recipient_email']}"
        )
    else:
        gw_spf = (
            f"Received-SPF: Pass ({GW_HOSTNAME}: domain of {sc['sender_email']}\n"
            f" designates {sc['attacker_ip']} as permitted sender) identity=mailfrom;\n"
            f" client-ip={sc['attacker_ip']}; helo={sc['attacker_host']};"
        )

    if sc["sfv"] == "SKN":
        cip_ip = sc["attacker_ip"]
        sfv_clause = f"SFV:SKN;H:{GW_HOSTNAME};PTR:{GW_HOSTNAME};CAT:{sc['threat_cat']};"
        rule_hist = f"X-MS-Exchange-Organization-Rules-ExecutionHistory: RuleId:{sc['bypass_rule_id']};RuleName:{sc['bypass_rule_name']};Action:SetSCL;RuleId:c19b4502-3901-4aa2-8710-1845bb094a11;RuleName:External Sender Warning;Action:PrependSubject,AddHeader;\n"
    elif sc["sfv"] == "NSPM" and sc["is_phish"]:
        cip_ip = sc["attacker_ip"]
        sfv_clause = f"SFV:NSPM;H:{GW_HOSTNAME};PTR:{GW_HOSTNAME};CAT:NONE;"
        rule_hist = f"X-MS-Exchange-Organization-Rules-ExecutionHistory: RuleId:c19b4502-3901-4aa2-8710-1845bb094a11;RuleName:External Sender Warning;Action:PrependSubject,AddHeader;\n"
    else:
        cip_ip = sc["attacker_ip"]
        sfv_clause = f"SFV:NSPM;H:{sc['attacker_host']};PTR:{sc['attacker_host']};CAT:NONE;"
        rule_hist = ""

    eml_text = f"""Received: from SJ0PR03MB7491.namprd03.prod.outlook.com (2603:10b6:408:149::19)
 by BL0PR03MB4812.namprd03.prod.outlook.com with HTTPS; {sc['t_eop_deliv'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
Received: from BN0PR03CA0041.namprd03.prod.outlook.com (2603:10b6:408:44::16)
 by SJ0PR03MB7491.namprd03.prod.outlook.com (2603:10b6:408:149::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9123.18; {sc['t_eop_deliv'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
Received: from {EOP_HOST}
 (2603:10b6:408:44:cafe::94) by BN0PR03CA0041.outlook.office365.com
 (2603:10b6:408:44::16) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9123.14 via Frontend
 Transport; {sc['t_eop_deliv'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
Authentication-Results: spf={sc['auth_results']['spf']} (sender IP is {sc['attacker_ip']})
 smtp.mailfrom={sc['attacker_domain']}; dkim={sc['auth_results']['dkim']}
 header.d={sc['attacker_domain'] if not sc['is_phish'] else 'none'}; dmarc={sc['auth_results']['dmarc']}
 compauth={sc['auth_results']['compauth']}
Received: from {GW_HOSTNAME} ({GW_EGRESS_IP}) by
 {EOP_HOST} ({EOP_IP}) with Microsoft SMTP
 Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9123.11 via
 Frontend Transport; {sc['t_relay'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
X-Gateway-Scanned: {GW_HOSTNAME} on {sc['t_relay'].strftime('%Y-%m-%d_%H:%M:%S')}
X-Gateway-Spam-Status: {'Yes' if sc['gateway_score'] >= 5.0 else 'No'}, score={sc['gateway_score']:.1f} required=5.0
X-Gateway-Spam-Score: {sc['gateway_score']:.1f}
{gw_spf}
{gw_recv}
Received: from {sc['attacker_host']} (localhost [127.0.0.1])
\tby {sc['attacker_host']} with ESMTP id {sc['attacker_queue_id']}
\tfor <{sc['recipient_email']}>; {sc['t_send'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
Date: {sc['t_send'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
To: "{sc['recipient_name']}" <{sc['recipient_email']}>
From: "{sc['sender_name']}" <{sc['sender_email']}>
Reply-To: {sc['reply_to']}
Subject: {sc['subject_delivered']}
Message-ID: {sc['message_id']}
{priority_headers}X-Mailer: {sc['mailer_str']}
MIME-Version: 1.0
Content-Type: multipart/alternative;
\tboundary="{sc['boundary']}"
Content-Transfer-Encoding: 8bit
X-External-Sender: {'YES' if sc['is_phish'] or 'EXTERNAL' in sc['subject_prefix'] else 'NO'}
X-EOPAttributedMessage: 0
X-MS-Exchange-Organization-MessageDirectionality: Inbound
X-MS-Exchange-Organization-AuthSource: {GW_HOSTNAME}
X-MS-Exchange-Organization-AuthAs: {'Anonymous' if sc['is_phish'] or sc['attacker_domain'] != 'contoso.com' else 'Internal'}
X-MS-Exchange-Organization-Network-Message-Id: {sc['network_message_id']}
{rule_hist}X-MS-Exchange-Organization-SCL: {sc['scl']}
X-MS-Exchange-Organization-PCL: 2
X-Forefront-Antispam-Report: CIP:{cip_ip};CTRY:US;LANG:en;SCL:{sc['scl']};SRV:DIR;IPV:CAL;{sfv_clause}SFS:(136003)(396003);DIR:INB;
X-Microsoft-Antispam: BCL:0;ARA:13230040|46104249079;
X-MS-Exchange-CrossTenant-OriginalArrivalTime: {sc['t_relay'].strftime('%d %b %Y %H:%M:%S.4100')} (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Internet
X-MS-Exchange-CrossTenant-Id: {TENANT_ID}
X-MS-Exchange-Transport-EndToEndLatency: 00:00:00.6800000
X-MS-Exchange-Processed-By-BccFoldering: 15.20.9123.018
X-Microsoft-Antispam-Mailbox-Delivery:
 ucf:0;jmr:0;auth:0;dest:I;ENG:(910001)(944506478)(944626604)(920097)(930097)(140003);
X-Microsoft-Antispam-Message-Info:
 {sc['antispam_b64']}

This is a multi-part message in MIME format.

--{sc['boundary']}
Content-Type: text/plain; charset=us-ascii

{sc['resolved_plain_body']}

--{sc['boundary']}
Content-Type: text/html; charset=us-ascii

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #333;">
<table width="600" cellpadding="0" cellspacing="0" style="border: 1px solid #ddd; padding: 20px;">
<tr><td>
<h2 style="color: #004b87;">{sc['html_headline']}</h2>
<p>Dear {sc['recipient_name']},</p>
<p>{sc['resolved_html_desc']}</p>
<p style="text-align: center; margin: 30px 0;">
<a href="{sc['resolved_url']}" style="background-color: #0078d4; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">{sc['html_action_btn']}</a>
</p>
<p><small>Reference Ticket: {sc['ref_ticket']}<br>Notice: Contoso Information Security will never ask for your credentials via unencrypted channels.</small></p>
</td></tr>
</table>
</body>
</html>

--{sc['boundary']}--
"""
    return eml_text.strip() + "\n"


def generate_postfix_syslog_lines(sc):
    lines = []

    def fmt(dt, comp, pid, msg):
        return (dt, f"{dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z {GW_HOSTNAME} postfix/{comp}[{pid}]: {msg}")

    client_str = f"unknown[{sc['attacker_ip']}]" if sc['is_phish'] else f"{sc['attacker_host']}[{sc['attacker_ip']}]"
    lines.append(fmt(sc["t_conn"], "smtpd", 48210, f"connect from {client_str}"))

    if sc["is_phish"]:
        lines.append(fmt(sc["t_rdns"], "smtpd", 48210, f"warning: hostname {sc['attacker_rdns_fake']} does not resolve to address {sc['attacker_ip']}: Name or service not known"))

    lines.append(fmt(sc["t_tls"], "smtpd", 48210, f"Anonymous TLS connection established from {client_str}: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256"))

    if sc["is_phish"]:
        lines.append(fmt(sc["t_spf"], "policyd-spf", 48218, f"prepend Received-SPF: SoftFail ({GW_HOSTNAME}: domain of transitioning {sc['sender_email']} does not designate {sc['attacker_ip']} as permitted sender) identity=mailfrom; client-ip={sc['attacker_ip']}; helo={sc['attacker_host']}; envelope-from={sc['sender_email']}; receiver={sc['recipient_email']}"))
        lines.append(fmt(sc["t_dkim"], "opendkim", 1104, f"{sc['queue_id']}: no signature data found for domain {sc['attacker_domain']}"))
        lines.append(fmt(sc["t_dmarc"], "dmarc-filter", 1180, f"{sc['queue_id']}: dmarc-result=fail (p=none sp=none pct=100) reason=\"SPF failed, DKIM missing\" domain={sc['attacker_domain']}"))
    else:
        lines.append(fmt(sc["t_spf"], "policyd-spf", 48218, f"prepend Received-SPF: Pass ({GW_HOSTNAME}: domain of {sc['sender_email']} designates {sc['attacker_ip']} as permitted sender) identity=mailfrom; client-ip={sc['attacker_ip']}; helo={sc['attacker_host']};"))
        lines.append(fmt(sc["t_dkim"], "opendkim", 1104, f"{sc['queue_id']}: DKIM signature verified: d={sc['attacker_domain']}"))

    lines.append(fmt(sc["t_queue"], "smtpd", 48210, f"{sc['queue_id']}: client={client_str}"))
    lines.append(fmt(sc["t_clean"], "cleanup", 48215, f"{sc['queue_id']}: message-id={sc['message_id']}"))

    scan_status = "SUSPICIOUS" if sc['is_phish'] else "CLEAN"
    lines.append(fmt(sc["t_spam"], "mailfilter", 48220, f"{sc['queue_id']}: Antivirus=CLEAN SpamCheck={scan_status} Score={sc['gateway_score']:.1f}/5.0 Action=TAG_HEADER"))

    lines.append(fmt(sc["t_qmgr"], "qmgr", 2814, f"{sc['queue_id']}: from=<{sc['sender_email']}>, size={sc['transit_size']}, nrcpt=1 (queue active)"))

    relay_msg = (
        f"{sc['queue_id']}: to=<{sc['recipient_email']}>, relay=contoso-com.mail.protection.outlook.com[{EOP_IP}]:25, "
        f"delay={sc['delay_total']:.1f}, delays={sc['delays_str']}, dsn=2.6.0, status=sent "
        f"(250 2.6.0 {sc['message_id']} [InternalId={sc['internal_id']}, Hostname=SJ0PR03MB7491.namprd03.prod.outlook.com] "
        f"{sc['delivered_size']} bytes in 0.281s, {sc['transfer_kbps']:.3f} KB/sec Queued mail for delivery)"
    )
    lines.append(fmt(sc["t_relay"], "smtp", 48225, relay_msg))
    lines.append(fmt(sc["t_del"], "qmgr", 2814, f"{sc['queue_id']}: removed"))
    lines.append(fmt(sc["t_disconn"], "smtpd", 48210, f"disconnect from {client_str} ehlo=2 starttls=1 mail=1 rcpt=1 data=1 quit=1 commands=7"))

    return lines


# ------------------------------------------------------------------------------
# INDIVIDUAL SMTP LOG GENERATOR (Syslog + Raw Session Capture per message)
# ------------------------------------------------------------------------------
def generate_individual_smtp_log(sc):
    lines = generate_postfix_syslog_lines(sc)
    syslog_text = "\n".join(line for _, line in lines)

    priority_headers = ""
    if sc["priority_high"]:
        priority_headers = "C: X-Priority: 1\nC: Priority: Urgent\nC: Importance: High\nC: X-MSMail-Priority: High\n"

    client_helo = sc["attacker_host"]
    client_ip = sc["attacker_ip"]
    client_name = f"unknown[{client_ip}]" if sc["is_phish"] else f"{client_helo}[{client_ip}]"

    raw_session = f"""[SESSION ID: {sc['queue_id']}]
[PEER: {client_ip}:48214 -> {GW_INGRESS_IP}:25]
[TIME: {sc['t_conn'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z]

S: 220 {GW_HOSTNAME} ESMTP Postfix (Ubuntu)
C: EHLO {client_helo}
S: 250-{GW_HOSTNAME}
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
C: EHLO {client_helo}
S: 250-{GW_HOSTNAME}
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
C: \tby {sc['attacker_host']} with ESMTP id {sc['attacker_queue_id']}
C: \tfor <{sc['recipient_email']}>; {sc['t_send'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
C: Date: {sc['t_send'].strftime('%a, %d %b %Y %H:%M:%S +0000')}
C: To: "{sc['recipient_name']}" <{sc['recipient_email']}>
C: From: "{sc['sender_name']}" <{sc['sender_email']}>
C: Reply-To: {sc['reply_to']}
C: Subject: {sc['subject_raw']}
C: Message-ID: {sc['message_id']}
{priority_headers}C: X-Mailer: {sc['mailer_str']}
C: MIME-Version: 1.0
C: Content-Type: multipart/alternative;
C: \tboundary="{sc['boundary']}"
C: Content-Transfer-Encoding: 8bit
C: 
C: This is a multi-part message in MIME format.
C: 
C: --{sc['boundary']}
C: Content-Type: text/plain; charset=us-ascii
C: 
C: {sc['resolved_plain_body'].replace(chr(10), chr(10) + 'C: ')}
C: 
C: --{sc['boundary']}
C: Content-Type: text/html; charset=us-ascii
C: 
C: <!DOCTYPE html>
C: <html>
C: <head><meta charset="utf-8"></head>
C: <body style="font-family: Arial, sans-serif; color: #333;">
C: <table width="600" cellpadding="0" cellspacing="0" style="border: 1px solid #ddd; padding: 20px;">
C: <tr><td>
C: <h2 style="color: #004b87;">{sc['html_headline']}</h2>
C: <p>Dear {sc['recipient_name']},</p>
C: <p>{sc['resolved_html_desc']}</p>
C: <p style="text-align: center; margin: 30px 0;">
C: <a href="{sc['resolved_url']}" style="background-color: #0078d4; color: white; padding: 12px 25px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">{sc['html_action_btn']}</a>
C: </p>
C: <p><small>Reference Ticket: {sc['ref_ticket']}<br>Notice: Contoso Information Security will never ask for your credentials via unencrypted channels.</small></p>
C: </td></tr>
C: </table>
C: </body>
C: </html>
C: 
C: --{sc['boundary']}--
C: .
S: 250 2.0.0 Ok: queued as {sc['queue_id']}
C: QUIT
S: 221 2.0.0 Bye"""

    log_content = f"""# ==============================================================================
# INBOUND SMTP GATEWAY LOG ({GW_HOSTNAME})
# Message Index: {sc['index']:02d} | Theme: {sc['theme']}
# Classification: {'PHISHING' if sc['is_phish'] else 'BENIGN'}
# Gateway Ingress Public IP: {GW_INGRESS_IP} / Gateway Egress Public IP: {GW_EGRESS_IP}
# Sender IP: {sc['attacker_ip']} ({client_name})
# Sender: "{sc['sender_name']}" <{sc['sender_email']}>
# Recipient: "{sc['recipient_name']}" <{sc['recipient_email']}>
# Queue ID: {sc['queue_id']} | Relay Target: {EOP_HOST} [{EOP_IP}]:25
# ==============================================================================

# --- SECTION 1: POSTFIX / MTA SESSION LOGS (SYSLOG RFC 3164) ---

{syslog_text}


# --- SECTION 2: RAW SMTP SESSION CAPTURE (mailgw01 INGRESS INTERFACE) ---

{raw_session}
"""
    return log_content.strip() + "\n"


def main():
    count = DEFAULT_COUNT
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass

    script_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(script_dir, "logs")
    emails_dir = os.path.join(logs_dir, "emails")
    smtp_dir = os.path.join(logs_dir, "smtp")

    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(emails_dir, exist_ok=True)
    os.makedirs(smtp_dir, exist_ok=True)

    # Clean old files in output subfolders
    for fname in os.listdir(emails_dir):
        if fname.endswith(".eml"):
            os.remove(os.path.join(emails_dir, fname))
    for fname in os.listdir(smtp_dir):
        if fname.endswith(".log"):
            os.remove(os.path.join(smtp_dir, fname))

    print(f"[*] Building {count} scenarios (reproducible seed={DEFAULT_SEED})...")
    scenarios = build_scenarios(count, seed=DEFAULT_SEED)

    for sc in scenarios:
        eml_type = "phish" if sc["is_phish"] else "benign"
        slug = sc["theme"].split('/')[0].split(':')[0].strip().lower().replace(' ', '_').replace('-', '_')
        base_name = f"msg_{sc['index']:02d}_{eml_type}_{slug}"

        # 1. EML File
        eml_filename = f"{base_name}.eml"
        eml_path = os.path.join(emails_dir, eml_filename)
        with open(eml_path, "w", encoding="utf-8") as f:
            f.write(generate_eml(sc))

        # 2. Individual SMTP Log File
        smtp_filename = f"{base_name}.log"
        smtp_path = os.path.join(smtp_dir, smtp_filename)
        with open(smtp_path, "w", encoding="utf-8") as f:
            f.write(generate_individual_smtp_log(sc))

    phish_count = sum(1 for s in scenarios if s["is_phish"])
    benign_count = count - phish_count

    print(f"\n[+] Successfully generated {count} scenarios ({phish_count} Phishing, {benign_count} Benign):")
    print(f"  -> Raw EML Files:        logs/emails/ ({len(os.listdir(emails_dir))} .eml files)")
    print(f"  -> Individual SMTP Logs: logs/smtp/   ({len(os.listdir(smtp_dir))} .log files)")


if __name__ == "__main__":
    main()
