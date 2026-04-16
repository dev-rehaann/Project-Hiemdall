import pytest
from firmware_module.uefi_parser import UEFIParser
from firmware_module.fake_firmware import make_test_firmware


@pytest.fixture
def basic_firmware():
    return make_test_firmware(include_dxe=True, include_smm=False)


@pytest.fixture
def smm_firmware():
    return make_test_firmware(include_dxe=True, include_smm=True)


@pytest.fixture
def smm_heuristic_firmware():
    return make_test_firmware(include_dxe=True, include_smm=False, smm_with_signature=True)


def test_finds_firmware_volume(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    assert len(parser.volumes) >= 1


def test_volume_has_valid_offset(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    for vol in parser.volumes:
        assert vol["offset"] >= 0
        assert vol["size"] > 0


def test_empty_blob_no_volumes():
    parser = UEFIParser(b"\x00" * 1024).parse()
    assert len(parser.volumes) == 0


def test_random_blob_no_crash():
    import os
    blob = os.urandom(4096)
    UEFIParser(blob).parse()


def test_extracts_ffs_files(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    assert len(parser.ffs_files) >= 1


def test_ffs_files_have_required_fields(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    for ffs in parser.ffs_files:
        assert "guid" in ffs
        assert "type" in ffs
        assert "type_name" in ffs
        assert "offset" in ffs
        assert "size" in ffs
        assert "body" in ffs


def test_ffs_guid_format(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    for ffs in parser.ffs_files:
        parts = ffs["guid"].split("-")
        assert len(parts) == 5


def test_detects_dxe_driver(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    assert len(parser.drivers) >= 1


def test_no_smm_in_clean_firmware(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    assert len(parser.smm_modules) == 0


def test_detects_smm_driver_by_type(smm_firmware):
    parser = UEFIParser(smm_firmware).parse()
    assert len(parser.smm_modules) >= 1


def test_detects_smm_by_signature_heuristic(smm_heuristic_firmware):
    parser = UEFIParser(smm_heuristic_firmware).parse()
    assert len(parser.smm_modules) >= 1


def test_get_summary_structure(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    summary = parser.get_summary()
    assert "firmware_size" in summary
    assert "volume_count" in summary
    assert "ffs_count" in summary
    assert "driver_count" in summary
    assert "smm_count" in summary
    assert "drivers" in summary
    assert "smm_modules" in summary


def test_summary_no_body_in_drivers(basic_firmware):
    parser = UEFIParser(basic_firmware).parse()
    summary = parser.get_summary()
    for driver in summary["drivers"]:
        assert "body" not in driver


def test_summary_counts_match(smm_firmware):
    parser = UEFIParser(smm_firmware).parse()
    summary = parser.get_summary()
    assert summary["volume_count"] == len(parser.volumes)
    assert summary["ffs_count"] == len(parser.ffs_files)
    assert summary["driver_count"] == len(parser.drivers)
    assert summary["smm_count"] == len(parser.smm_modules)