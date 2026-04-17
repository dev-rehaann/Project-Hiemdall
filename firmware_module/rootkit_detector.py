import hashlib
from pathlib import Path
from rich.console import Console

_con = Console()

# Known rootkit database - hashes + GUIDs + string indicators        

KNOWN_ROOTKITS = {
    "LoJax": {
        "family":   "Sednit / APT28",
        "severity": "CRITICAL",
        "guids": [
            "D84163B6-2B4B-4AF0-9A8E-7C96B6C4D2E1",
        ],
        "strings": [
            b"HddS.M.S",
            b"LoJax",
        ],
        "sha256": [],   # Add real hashes on Samples
    },
    "CosmicStrand": {
        "family":   "Unknown (Chinese-nexus suspected)",
        "severity": "CRITICAL",
        "guids": [],
        "strings": [
            b"CosmicStrand",
            b"__security_init_cookie",
        ],
        "sha256": [],
    },
    "BlackLotus": {
        "family":   "UEFI Bootkit",
        "severity": "CRITICAL",
        "guids": [],
        "strings": [
            b"BlackLotus",
            b"bootmgfw.efi",
        ],
        "sha256": [],
    },
    "MosaicRegressor": {
        "family":   "Lazarus Group",
        "severity": "CRITICAL",
        "guids": [],
        "strings": [
            b"MosaicRegressor",
        ],
        "sha256": [],
    },
}

# Byte patterns that are suspicious in any driver regardless of family
GENERIC_SUSPICIOUS_STRINGS = [
    b"SmmConfigurationTable",
    b"SmmAllocatePool",
    b"SmmAllocatePages",
    b"EFI_SMM_SYSTEM_TABLE",
    b"gSmst",
    b"SmmInstallProtocolInterface",
    b"EFI_SMM_BASE2_PROTOCOL",
]


# Detector                                                            

class RootkitDetector:
    """
    Scans parsed UEFI drivers for rootkit indicators using three layers:
    1. Hash matching against known-bad SHA256 values
    2. String/GUID matching against known rootkit indicators
    3. Heuristic checks 
    """

    def __init__(self, rules_dir=None):
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).parent / "rules"
        self.yara_available = self._check_yara()
        self.yara_rules = self._load_yara_rules() if self.yara_available else None

        if not self.yara_available:
            _con.print("[yellow]Warning:[/yellow] yara-python not installed - YARA scanning disabled")
            _con.print("[dim]Install with: pip install yara-python[/dim]")

    # Public API

    def scan_driver(self, driver: dict) -> list[dict]:
        """
        Scan a single driver dict for rootkit indicators.
        Returns a list of finding dicts - empty list means clean.
        """
        body    = driver.get("body", b"")
        guid    = driver.get("guid", "")
        findings = []

        # Layer 1: hash matching
        findings += self._check_hashes(body)

        # Layer 2: known rootkit string + GUID matching
        findings += self._check_known_rootkits(body, guid)

        # Layer 3: heuristics
        findings += self._check_heuristics(body, driver)

        # Layer 4: YARA 
        if self.yara_available and self.yara_rules:
            findings += self._yara_scan(body)

        return findings

    def scan_all_drivers(self, drivers: list[dict]) -> dict:
        """
        Scan a list of drivers (from UEFIParser.drivers + smm_modules).
        Returns a summary dict with per-driver findings.
        """
        results = {
            "total_scanned": len(drivers),
            "total_findings": 0,
            "clean": [],
            "flagged": [],
        }

        for driver in drivers:
            findings = self.scan_driver(driver)
            entry = {
                "guid":      driver.get("guid", "unknown"),
                "type_name": driver.get("type_name", "unknown"),
                "offset":    driver.get("offset", 0),
                "size":      driver.get("size", 0),
                "findings":  findings,
            }

            if findings:
                results["flagged"].append(entry)
                results["total_findings"] += len(findings)
                self._print_finding(entry)
            else:
                results["clean"].append(entry)

        return results

    # Layer 1 - Hash matching

    def _check_hashes(self, body: bytes) -> list[dict]:
        findings = []
        sha256 = hashlib.sha256(body).hexdigest()
        md5    = hashlib.md5(body).hexdigest()

        for rootkit_name, indicators in KNOWN_ROOTKITS.items():
            if sha256 in indicators.get("sha256", []):
                findings.append({
                    "type":       "known_rootkit_hash",
                    "rootkit":    rootkit_name,
                    "family":     indicators["family"],
                    "confidence": "HIGH",
                    "severity":   indicators["severity"],
                    "detail":     f"SHA256 match: {sha256}",
                })

        return findings

    # Layer 2 - Known rootkit string + GUID indicators

    def _check_known_rootkits(self, body: bytes, guid: str) -> list[dict]:
        findings = []

        for rootkit_name, indicators in KNOWN_ROOTKITS.items():
            matched_strings = []
            matched_guids   = []

            # Check GUIDs
            for known_guid in indicators.get("guids", []):
                if known_guid.upper() == guid.upper():
                    matched_guids.append(known_guid)

            # Check byte strings
            for sig in indicators.get("strings", []):
                if sig in body:
                    matched_strings.append(sig.decode("utf-8", errors="replace"))

            if matched_strings or matched_guids:
                confidence = "HIGH" if (matched_guids or len(matched_strings) >= 2) else "MEDIUM"
                findings.append({
                    "type":            "known_rootkit_indicator",
                    "rootkit":         rootkit_name,
                    "family":          indicators["family"],
                    "confidence":      confidence,
                    "severity":        indicators["severity"],
                    "matched_strings": matched_strings,
                    "matched_guids":   matched_guids,
                    "detail":          f"Matched {len(matched_strings)} string(s), {len(matched_guids)} GUID(s)",
                })

        return findings

    # Layer 3 - Heuristics

    def _check_heuristics(self, body: bytes, driver: dict) -> list[dict]:
        findings = []

        # Check 1: SMM driver without WinCert signature
        is_smm_type = driver.get("type_name", "") in ["SMM_DRIVER"]
        has_smm_strings = any(s in body for s in GENERIC_SUSPICIOUS_STRINGS)
        has_win_cert = b"WIN_CERT" in body

        if (is_smm_type or has_smm_strings) and not has_win_cert:
            findings.append({
                "type":       "unsigned_smm",
                "confidence": "MEDIUM",
                "severity":   "HIGH",
                "detail":     "SMM-capable driver lacks WinCert signature block",
            })

        # Check 2: Multiple SMM allocation calls - common in persistent implants
        alloc_count = sum(
            1 for s in [b"SmmAllocatePool", b"SmmAllocatePages"]
            if s in body
        )
        if alloc_count >= 2:
            findings.append({
                "type":       "suspicious_smm_allocation",
                "confidence": "MEDIUM",
                "severity":   "HIGH",
                "detail":     f"Driver calls {alloc_count} SMM allocation functions",
            })

        # Check 3: Suspiciously small driver body - possible stub/loader
        if 0 < len(body) < 512 and has_smm_strings:
            findings.append({
                "type":       "tiny_smm_stub",
                "confidence": "LOW",
                "severity":   "MEDIUM",
                "detail":     f"Tiny driver ({len(body)} bytes) with SMM references - possible loader stub",
            })

        return findings

    # Layer 4 - YARA                                         

    def _yara_scan(self, body: bytes) -> list[dict]:
        findings = []
        try:
            matches = self.yara_rules.match(data=body)
            for match in matches:
                meta = match.meta
                findings.append({
                    "type":       "yara_match",
                    "rule":       match.rule,
                    "confidence": "HIGH",
                    "severity":   meta.get("severity", "MEDIUM"),
                    "detail":     meta.get("description", "YARA rule matched"),
                    "family":     meta.get("family", "unknown"),
                })
        except Exception as e:
            _con.print(f"[yellow]YARA scan error:[/yellow] {e}")
        return findings

    # YARA setup

    def _check_yara(self) -> bool:
        try:
            import yara
            return True
        except ImportError:
            return False

    def _load_yara_rules(self):
        try:
            import yara
            rule_files = {}

            uefi_rules = self.rules_dir / "uefi_rootkits.yar"
            smm_rules  = self.rules_dir / "smm_suspicious.yar"

            if uefi_rules.exists():
                rule_files["uefi_rootkits"] = str(uefi_rules)
            if smm_rules.exists():
                rule_files["smm_suspicious"] = str(smm_rules)

            if not rule_files:
                _con.print("[yellow]Warning:[/yellow] No YARA rule files found in rules/")
                return None

            return yara.compile(filepaths=rule_files)
        except Exception as e:
            _con.print(f"[yellow]Warning:[/yellow] Could not load YARA rules: {e}")
            return None

    # Output helper

    def _print_finding(self, entry: dict):
        guid = entry["guid"]
        _con.print(f"\n[bold red]⚠ FLAGGED DRIVER[/bold red] - GUID: {guid}")
        for f in entry["findings"]:
            sev   = f.get("severity", "MEDIUM")
            color = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "blue"
            _con.print(f"  [{color}][{sev}][/{color}] {f['type']} - {f['detail']}")