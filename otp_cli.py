#!/usr/bin/env python3
"""
Minimal AADE 39A OTP helper as a CLI.
Default: test mode with built-in credentials.
"""

import argparse
import sys
import textwrap
import requests
import xml.etree.ElementTree as ET

# To generate credentials for blokaki ("personal business" thingy), just log in with personal creds to taxisnet in:
# https://www1.aade.gr/sgsisapps/tokenservices/protected/displayConsole.htm and click (Υπηρεσία άρθρου 39α, παρ.5 κώδικα ΦΠΑ (ΠΟΛ 1150/29.9.2017) - Δημιουργία Ειδικού Κωδικού)
# for a normal business, you must dictate the target physical person as a representitive. Authenticated with the business creds at taxisnet:
# https://www1.aade.gr/taxisnet/mytaxisnet/protected/authorizations.htm - at the waaaay bottom you must be a representitive, in the "Εκπρόσωπους του νομικού μου προσώπου" table
# afterwards follow the instructions above

# From https://www.aade.gr/dl_assets/39afpa/developer_env_aade39afpa_v1.1.pdf
TEST_CREDS = dict(
    username="TEST39AFPA05PKV",
    password="TEST39AFPA05PKV",
    buyer_afm="660073151",
    rep_afm="660073151",
)

TEST_URL = "https://test.gsis.gr/wsaade/VtWs39aFPA/VtWs39aFPA"
LIVE_URL = "https://www1.gsis.gr/wsaade/VtWs39aFPA/VtWs39aFPA"

NS = {
    "env": "http://www.w3.org/2003/05/soap-envelope",
    "ns1": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "ns2": "http://vtws39afpa/VtWs39aFPAService",
    "ns3": "http://vtws39afpa/VtWs39aFPA",
}


def envelope(username: str, password: str, body: str) -> str:
    return textwrap.dedent(f"""
<?xml version='1.0' encoding='UTF-8'?>
<env:Envelope
xmlns:env="{NS['env']}"
xmlns:ns1="{NS['ns1']}"
xmlns:ns2="{NS['ns2']}"
xmlns:ns3="{NS['ns3']}">
  <env:Header>
    <ns1:Security>
      <ns1:UsernameToken>
        <ns1:Username>{username}</ns1:Username>
        <ns1:Password>{password}</ns1:Password>
      </ns1:UsernameToken>
    </ns1:Security>
  </env:Header>
  <env:Body>
    {body}
  </env:Body>
</env:Envelope>
    """).strip()


def call(endpoint: str, xml_body: str, action: str):
    # print(f"endpoint {endpoint} body:\n{xml_body}")
    resp = requests.post(
        endpoint,
        data=xml_body.encode("utf-8"),
        headers={
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
            "39aClientVersion": "1.0.5",
        },
        timeout=30,
    )

    if resp.status_code != 200:
        print(f"{resp.status_code} Full response:\n\n{resp.text}")
        resp.raise_for_status()
    return resp.text


def parse_message(root: ET.Element):
    code = root.find(".//ns3:message_code", NS)
    descr = root.find(".//ns3:message_descr", NS)
    if code is not None and (code.text or "").strip():
        return (code.text or "").strip(), (descr.text or "").strip()
    return None


def step_validate(endpoint, uname, pw, buyer_afm):
    body = f"""
    <ns2:vt39afpaBu3GetBuyer>
      <ns3:BU3_IN_REC>
        <ns3:buyer_afm>{buyer_afm}</ns3:buyer_afm>
      </ns3:BU3_IN_REC>
    </ns2:vt39afpaBu3GetBuyer>
    """
    xml = envelope(uname, pw, body)
    print("1) Validating buyer (Bu3)…", flush=True)
    text = call(endpoint, xml, "http://vtws39afpa/VtWs39aFPAService/vt39afpaBu3GetBuyer")
    root = ET.fromstring(text)
    msg = parse_message(root)
    if msg:
        print(f"Error: {msg[0]} - {msg[1]}")
        print(f"Full response:\n\n{text}")
        return None
    fullname = root.find(".//ns3:buyer_fullname", NS)
    if fullname is None or not (fullname.text or "").strip():
        print("Error: fullname not returned.")
        return None
    name = fullname.text.strip()
    print(f"✓ Buyer validated. Full name: {name}")
    return name


def step_init(endpoint, uname, pw, buyer_afm):
    body = f"""
    <ns2:vt39afpaBu1SetBuyer>
      <ns3:BU1_IN_REC>
        <ns3:buyer_afm>{buyer_afm}</ns3:buyer_afm>
      </ns3:BU1_IN_REC>
    </ns2:vt39afpaBu1SetBuyer>
    """
    xml = envelope(uname, pw, body)
    print("0) Initializing buyer (Bu1)…", flush=True)
    text = call(endpoint, xml, "http://vtws39afpa/VtWs39aFPAService/vt39afpaBu1SetBuyer")
    root = ET.fromstring(text)
    msg = parse_message(root)
    if msg:
        print(f"Error: {msg[0]} - {msg[1]}")
        print(f"Full response:\n\n{text}")
        return False
    print()
    print("Response:")
    print(text)
    print()
    print("✓ Buyer initialization call completed.")
    return True


def step_otp(endpoint, uname, pw, buyer_afm, rep_afm, size, days):
    size_xml = f"<ns3:otp_size_requested>{size}</ns3:otp_size_requested>" if size else ""
    days_xml = f"<ns3:otp_days_to_live>{days}</ns3:otp_days_to_live>" if days else ""
    body = f"""
    <ns2:vt39afpaBu9GetOtp>
      <ns3:BU9_IN_REC>
        <ns3:buyer_afm>{buyer_afm}</ns3:buyer_afm>
        <ns3:repr_afm>{rep_afm}</ns3:repr_afm>
        <ns3:otp_action_requested>C</ns3:otp_action_requested>
        {size_xml}
        {days_xml}
      </ns3:BU9_IN_REC>
    </ns2:vt39afpaBu9GetOtp>
    """
    xml = envelope(uname, pw, body)
    print("2) Requesting OTP (Bu9)…", flush=True)
    text = call(endpoint, xml, "http://vtws39afpa/VtWs39aFPAService/vt39afpaBu9GetOtp")
    root = ET.fromstring(text)
    msg = parse_message(root)
    if msg:
        print(f"Error: {msg[0]} - {msg[1]}")
        return False

    otp_id = root.find(".//ns3:otp_id", NS)
    if otp_id is None or not (otp_id.text or "").strip():
        # fallback: first item in table
        otp_id = root.find(".//ns3:bu9_otpout_tab//ns3:item//ns3:otp_id", NS)
    if otp_id is None or not (otp_id.text or "").strip():
        print("Error: OTP not returned.")
        return False
    print(f"✓ OTP generated: {otp_id.text.strip()}")
    start = root.find(".//ns3:otp_valid_start_datetime", NS)
    end = root.find(".//ns3:otp_valid_end_datetime", NS)
    if start is not None and end is not None:
        print(f"   Valid from {start.text.strip()} to {end.text.strip()}")
    return True


def main():
    p = argparse.ArgumentParser(description="AADE 39A OTP generator (CLI, minimal).")
    p.add_argument("--username")
    p.add_argument("--password")
    p.add_argument("--buyer-afm")
    p.add_argument("--rep-afm")
    p.add_argument("--otp-size", type=int, default=1)
    p.add_argument("--otp-days", type=int, default=1)
    p.add_argument("--live", action="store_true", help="Use live endpoint (default test).")
    p.add_argument("--test", action="store_true", help="Force test creds/endpoint.")
    p.add_argument("--init", action="store_true", help="Call Bu1 setBuyer before validation.")
    args = p.parse_args()

    # Decide creds and endpoint
    provided_core = any([args.username, args.password, args.buyer_afm, args.rep_afm])
    use_test_creds = args.test or not provided_core

    endpoint = TEST_URL if (use_test_creds or not args.live) else LIVE_URL
    uname = args.username or (TEST_CREDS["username"] if use_test_creds else None)
    pw = args.password or (TEST_CREDS["password"] if use_test_creds else None)
    buyer_afm = args.buyer_afm or (TEST_CREDS["buyer_afm"] if use_test_creds else None)
    rep_afm = args.rep_afm or (TEST_CREDS["rep_afm"] if use_test_creds else buyer_afm)

    missing = [k for k, v in dict(username=uname, password=pw, buyer_afm=buyer_afm, rep_afm=rep_afm).items() if not v]
    if missing:
        print(f"Missing required fields: {', '.join(missing)}")
        sys.exit(1)

    if args.init:
        ok_init = step_init(endpoint, uname, pw, buyer_afm)
        if not ok_init:
            sys.exit(1)

    name = step_validate(endpoint, uname, pw, buyer_afm)
    if not name:
        sys.exit(1)
    ok = step_otp(endpoint, uname, pw, buyer_afm, rep_afm, args.otp_size, args.otp_days)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
