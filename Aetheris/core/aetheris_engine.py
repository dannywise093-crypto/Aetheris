import os
import sys
import time
import yaml
import logging
import argparse
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTIONS_DIR = os.path.join(BASE_DIR, "detections")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

os.makedirs(DETECTIONS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="[AETHERIS-CORE] %(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(LOGS_DIR, "aetheris_defense.log"),
            encoding="utf-8"
        )
    ]
)


class DeceptionHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        source_ip = self.client_address[0]

        logging.warning(
            "[HONEYPOT] Connection detected from %s path=%s",
            source_ip,
            self.path
        )

        AetherisEngine.register_external_strike(
            source_ip,
            "Honeypot interaction"
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        self.wfile.write(
            b"<html><body><h1>Aetheris Security Monitor</h1></body></html>"
        )

    def log_message(self, format, *args):
        return


class AetherisSIEMAnalyzer:

    def __init__(self, rules_dir=DETECTIONS_DIR):
        self.rules_dir = rules_dir
        self.rules = self.load_sigma_rules()

    def load_sigma_rules(self):
        rules = []

        default_rule = {
            "title": "Suspicious LSASS Access",
            "id": "ae-001-sig",
            "detection": {
                "selection": {
                    "EventID": 10,
                    "TargetImage|endswith": "\\lsass.exe"
                }
            }
        }

        rule_path = os.path.join(
            self.rules_dir,
            "default_rule.yml"
        )

        if not os.path.exists(rule_path):
            with open(rule_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(default_rule, f)

        for root, _, files in os.walk(self.rules_dir):
            for filename in files:
                if filename.endswith((".yml", ".yaml")):
                    path = os.path.join(root, filename)

                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            rule = yaml.safe_load(f)

                        if rule:
                            rules.append(rule)

                    except Exception as exc:
                        logging.error(
                            "Could not load rule %s: %s",
                            filename,
                            exc
                        )

        logging.info("Loaded %d detection rule(s)", len(rules))
        return rules

    def evaluate(self, event):
        for rule in self.rules:
            selection = rule.get("detection", {}).get("selection", {})
            matched = True

            for key, expected in selection.items():

                if "|endswith" in key:
                    field = key.split("|")[0]

                    if field not in event:
                        matched = False
                        break

                    if not str(event[field]).endswith(expected):
                        matched = False
                        break

                else:
                    if event.get(key) != expected:
                        matched = False
                        break

            if matched:
                logging.critical(
                    "[SIEM] Detection triggered: %s",
                    rule.get("title", "Unnamed rule")
                )
                return True

        return False


class AetherisEngine:

    blocked_hosts = set()
    siem = AetherisSIEMAnalyzer()

    @classmethod
    def register_external_strike(cls, ip_address, vector):

        if ip_address in cls.blocked_hosts:
            logging.info(
                "[CONTAINMENT] %s already contained",
                ip_address
            )
            return

        cls.blocked_hosts.add(ip_address)

        logging.critical("=" * 60)
        logging.critical("[AETHERIS DEFENSE PROTOCOL]")
        logging.critical("Source: %s", ip_address)
        logging.critical("Vector: %s", vector)
        logging.critical(
            "Action: local containment record created"
        )
        logging.critical("=" * 60)

        cls.write_containment_record(ip_address, vector)

    @classmethod
    def write_containment_record(cls, ip_address, vector):

        path = os.path.join(
            LOGS_DIR,
            "containment.log"
        )

        with open(path, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.now().isoformat()} | "
                f"source={ip_address} | "
                f"vector={vector}\n"
            )

    @classmethod
    def process_telemetry_event(cls, event):

        severity = event.get("severity", "LOW")
        source_ip = event.get("source_ip")

        detected = cls.siem.evaluate(event)

        if detected or severity.upper() == "HIGH":

            if source_ip:
                cls.register_external_strike(
                    source_ip,
                    event.get(
                        "vector",
                        "Unknown security event"
                    )
                )


def start_deception_server():

    address = ("0.0.0.0", 8443)

    server = HTTPServer(
        address,
        DeceptionHandler
    )

    logging.info(
        "Aetheris honeypot listening on port 8443"
    )

    server.serve_forever()


def run_automated_pipeline():

    logging.info(
        "Initializing Aetheris defensive monitoring..."
    )

    server_thread = threading.Thread(
        target=start_deception_server,
        daemon=True
    )

    server_thread.start()

    time.sleep(1)

    sample_event = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": "203.0.113.42",
        "vector": "Test security event",
        "severity": "HIGH",
        "EventID": 10,
        "TargetImage": r"C:\Windows\System32\lsass.exe"
    }

    logging.info("Running defensive telemetry test...")

    AetherisEngine.process_telemetry_event(
        sample_event
    )

    logging.info(
        "Aetheris is running. Press Ctrl+C to stop."
    )

    try:
        while True:
            time.sleep(3600)

    except KeyboardInterrupt:
        logging.info(
            "Aetheris shutting down."
        )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Aetheris Defensive Security Engine"
    )

    parser.add_argument(
        "--start",
        action="store_true",
        help="Start Aetheris"
    )

    args = parser.parse_args()

    run_automated_pipeline()
