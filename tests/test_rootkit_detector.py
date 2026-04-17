import pytest
from firmware_module.rootkit_detector import RootkitDetector
from firmware_module.fake_firmware import make_test_firmware
from firmware_module.uefi_parser import UEFIParser


@pytest.fixture
def detector():
    return RootkitDetector()


@pytest.fixture
def clean_drivers():
    fw = make_test_firmware(include_dxe=True, include_smm=False)
    parser = UEFIParser(fw).parse()
    return parser.drivers + parser.smm_modules


@pytest.fixture
def smm_drivers():
    fw = make_test_firmware(include_dxe=True, include_smm=True)
    parser = UEFIParser(fw).parse()
    return parser.drivers + parser.smm_modules


def make_fake_driver(body: bytes, type_name: str = "DXE_DRIVER") -> dict:
    """Helper to build a minimal driver dict for testing"""
    return {
        "guid":      "AAAAAAAA-0000-0000-0000-000000000000",
        "type":      0x06,
        "type_name": type_name,
        "offset":    0,
        "size":      len(body),
        "body":      body,
    }


# Detector initialization

def test_detector_initializes(detector):
    assert detector is not None


def test_detector_has_yara_flag(detector):
    assert isinstance(detector.yara_available, bool)


# Hash matching

def test_clean_body_no_hash_match(detector):
    driver = make_fake_driver(b"\x00" * 256)
    findings = detector._check_hashes(driver["body"])
    assert findings == []


# Known rootkit string matching

def test_detects_lojax_string(detector):
    body = b"some firmware data HddS.M.S more data"
    driver = make_fake_driver(body)
    findings = detector._check_known_rootkits(body, driver["guid"])
    rootkits_found = [f["rootkit"] for f in findings]
    assert "LoJax" in rootkits_found


def test_detects_blacklotus_string(detector):
    body = b"data BlackLotus more data"
    findings = detector._check_known_rootkits(body, "AAAAAAAA-0000-0000-0000-000000000000")
    rootkits_found = [f["rootkit"] for f in findings]
    assert "BlackLotus" in rootkits_found


def test_detects_lojax_guid(detector):
    body = b"\x00" * 128
    guid = "D84163B6-2B4B-4AF0-9A8E-7C96B6C4D2E1"
    findings = detector._check_known_rootkits(body, guid)
    rootkits_found = [f["rootkit"] for f in findings]
    assert "LoJax" in rootkits_found


def test_clean_driver_no_string_match(detector):
    body = b"totally clean driver body with nothing suspicious"
    findings = detector._check_known_rootkits(body, "AAAAAAAA-0000-0000-0000-000000000000")
    assert findings == []


def test_high_confidence_on_guid_match(detector):
    body = b"\x00" * 128
    guid = "D84163B6-2B4B-4AF0-9A8E-7C96B6C4D2E1"
    findings = detector._check_known_rootkits(body, guid)
    assert findings[0]["confidence"] == "HIGH"


# Heuristics

def test_unsigned_smm_flagged(detector):
    body = b"SmmConfigurationTable" + b"\x00" * 128
    driver = make_fake_driver(body, type_name="SMM_DRIVER")
    findings = detector._check_heuristics(body, driver)
    types = [f["type"] for f in findings]
    assert "unsigned_smm" in types


def test_signed_smm_not_flagged(detector):
    body = b"SmmConfigurationTable WIN_CERT valid_signature_here" + b"\x00" * 64
    driver = make_fake_driver(body, type_name="SMM_DRIVER")
    findings = detector._check_heuristics(body, driver)
    types = [f["type"] for f in findings]
    assert "unsigned_smm" not in types


def test_multiple_smm_allocs_flagged(detector):
    body = b"SmmAllocatePool SmmAllocatePages" + b"\x00" * 64
    driver = make_fake_driver(body)
    findings = detector._check_heuristics(body, driver)
    types = [f["type"] for f in findings]
    assert "suspicious_smm_allocation" in types


def test_clean_dxe_no_heuristic_flags(detector):
    body = b"DXE_DRIVER_BODY" + b"\x00" * 128
    driver = make_fake_driver(body, type_name="DXE_DRIVER")
    findings = detector._check_heuristics(body, driver)
    assert findings == []


# Full scan pipeline

def test_scan_driver_returns_list(detector, clean_drivers):
    for d in clean_drivers:
        result = detector.scan_driver(d)
        assert isinstance(result, list)


def test_scan_all_returns_summary(detector, clean_drivers):
    summary = detector.scan_all_drivers(clean_drivers)
    assert "total_scanned" in summary
    assert "total_findings" in summary
    assert "clean" in summary
    assert "flagged" in summary


def test_scan_all_counts_correct(detector, clean_drivers):
    summary = detector.scan_all_drivers(clean_drivers)
    assert summary["total_scanned"] == len(clean_drivers)
    total = len(summary["clean"]) + len(summary["flagged"])
    assert total == summary["total_scanned"]


def test_lojax_driver_gets_flagged(detector):
    body = b"HddS.M.S LoJax" + b"\x00" * 128
    driver = make_fake_driver(body)
    findings = detector.scan_driver(driver)
    assert len(findings) > 0