import struct
from pathlib import Path
from rich.console import Console as RichConsole

_console = RichConsole()

# ------------------------------------------------------------------ #
#  UEFI Constants                                                      #
# ------------------------------------------------------------------ #

FV_SIGNATURE = b"_FVH"          # Firmware Volume header signature
FFS_HEADER_SIZE = 24             # Standard FFS file header size in bytes

# FFS File Types we care about
FFS_TYPE_RAW            = 0x01
FFS_TYPE_FREEFORM       = 0x02
FFS_TYPE_SECURITY_CORE  = 0x03
FFS_TYPE_PEI_CORE       = 0x04
FFS_TYPE_DXE_CORE       = 0x05
FFS_TYPE_DXE_DRIVER     = 0x06
FFS_TYPE_APPLICATION    = 0x09
FFS_TYPE_SMM_DRIVER     = 0x0A

DXE_TYPES = {
    FFS_TYPE_DXE_CORE,
    FFS_TYPE_DXE_DRIVER,
    FFS_TYPE_APPLICATION,
}

SMM_TYPES = {
    FFS_TYPE_SMM_DRIVER,
}

# Known SMM-related byte strings we look for inside driver bodies
SMM_SIGNATURES = [
    b"SmmConfigurationTable",
    b"EFI_SMM_SYSTEM_TABLE",
    b"gSmst",
    b"SmmInstallProtocolInterface",
    b"EFI_SMM_BASE2_PROTOCOL",
]


# ------------------------------------------------------------------ #
#  Main Parser Class                                                   #
# ------------------------------------------------------------------ #

class UEFIParser:
    """
    Parses a raw UEFI firmware blob into:
      - Firmware Volumes (FV)
      - FFS files within each volume
      - DXE drivers
      - SMM modules (highest privilege — primary rootkit target)
    """

    def __init__(self, firmware_blob: bytes):
        self.blob = firmware_blob
        self.size = len(firmware_blob)

        self.volumes   = []   # List of parsed firmware volumes
        self.ffs_files = []   # All FFS files found across all volumes
        self.drivers   = []   # DXE drivers
        self.smm_modules = [] # SMM modules — the scary ones

    # ---------------------------------------------------------------- #
    #  Public API                                                        #
    # ---------------------------------------------------------------- #

    def parse(self):
        """
        Full parse pipeline — call this first.
        Runs volume scan → FFS extraction → driver/SMM classification.
        """
        _console.print("[bold]Starting UEFI firmware parse...[/bold]")

        self._scan_firmware_volumes()
        _console.print(f"  Found [cyan]{len(self.volumes)}[/cyan] firmware volume(s)")

        self._extract_ffs_files()
        _console.print(f"  Found [cyan]{len(self.ffs_files)}[/cyan] FFS file(s)")

        self._classify_drivers()
        _console.print(f"  DXE drivers : [cyan]{len(self.drivers)}[/cyan]")
        _console.print(f"  SMM modules : [{'red' if self.smm_modules else 'cyan'}]{len(self.smm_modules)}[/{'red' if self.smm_modules else 'cyan'}]")

        return self

    def get_summary(self):
        """Return a plain dict summary — used by other modules and reports"""
        return {
            "firmware_size": self.size,
            "volume_count": len(self.volumes),
            "ffs_count": len(self.ffs_files),
            "driver_count": len(self.drivers),
            "smm_count": len(self.smm_modules),
            "volumes": self.volumes,
            "drivers": [self._driver_summary(d) for d in self.drivers],
            "smm_modules": [self._driver_summary(d) for d in self.smm_modules],
        }

    # ---------------------------------------------------------------- #
    #  Step 1 — Scan for Firmware Volumes                               #
    # ---------------------------------------------------------------- #

    def _scan_firmware_volumes(self):
        """
        Walk the blob looking for '_FVH' signature.
        NOTE: _FVH is at byte 40 inside the FV header, not byte 0.
        So when we find it at position X, the header actually starts at X - 40.
        """
        self.volumes = []
        offset = 0

        while offset < self.size - 4:
            if self.blob[offset:offset + 4] == FV_SIGNATURE:
                # Rewind 40 bytes to get to the real header start
                fv_start = offset - 40
                if fv_start >= 0:
                    fv = self._parse_fv_header(fv_start)
                    if fv:
                        self.volumes.append(fv)
                        next_offset = fv_start + fv["size"]
                        if next_offset <= offset:
                            offset += 8
                        else:
                            offset = next_offset
                        continue
            offset += 1

    def _parse_fv_header(self, offset):
        """
        Parse the EFI_FIRMWARE_VOLUME_HEADER structure.

        Layout (relevant fields):
          +00  ZeroVector[16]
          +16  FileSystemGuid[16]
          +32  FvLength         (8 bytes, uint64)
          +40  Signature        (4 bytes, '_FVH')
          +44  Attributes       (4 bytes)
          +48  HeaderLength     (2 bytes)
          +50  Checksum         (2 bytes)
          +52  ExtHeaderOffset  (2 bytes)
          +54  Reserved         (1 byte)
          +55  Revision         (1 byte)
        """
        # Need at least 56 bytes for a valid FV header
        if offset + 56 > self.size:
            return None

        try:
            fv_length    = struct.unpack_from("<Q", self.blob, offset + 32)[0]
            attributes   = struct.unpack_from("<I", self.blob, offset + 44)[0]
            header_length = struct.unpack_from("<H", self.blob, offset + 48)[0]
            revision     = struct.unpack_from("<B", self.blob, offset + 55)[0]

            # Basic sanity checks
            if fv_length == 0 or fv_length > self.size:
                return None
            if header_length < 56:
                return None

            return {
                "offset": offset,
                "size": fv_length,
                "header_length": header_length,
                "attributes": attributes,
                "revision": revision,
                "data_offset": offset + header_length,  # Where FFS files start
            }

        except struct.error:
            return None

    # ---------------------------------------------------------------- #
    #  Step 2 — Extract FFS Files from each Volume                      #
    # ---------------------------------------------------------------- #

    def _extract_ffs_files(self):
        """
        Each Firmware Volume contains FFS (Firmware File System) files.
        Walk each volume's data region and extract them.
        """
        self.ffs_files = []

        for vol in self.volumes:
            vol_start  = vol["data_offset"]
            vol_end    = vol["offset"] + vol["size"]

            if vol_start >= vol_end:
                continue

            self._parse_ffs_in_range(vol_start, vol_end, vol["offset"])

    def _parse_ffs_in_range(self, start, end, volume_offset):
        """
        Walk a byte range parsing FFS file headers.

        EFI_FFS_FILE_HEADER layout:
          +00  Name (GUID, 16 bytes)
          +16  IntegrityCheck (2 bytes)
          +18  Type (1 byte)
          +19  Attributes (1 byte)
          +20  Size[3] (3 bytes, uint24 little-endian)
          +23  State (1 byte)
        Total header = 24 bytes
        """
        offset = start

        while offset < end - FFS_HEADER_SIZE:
            # 8-byte alignment is required between FFS files
            if offset % 8 != 0:
                offset += 8 - (offset % 8)

            if offset + FFS_HEADER_SIZE > end:
                break

            try:
                # Read GUID (16 bytes) as raw hex string
                guid_bytes = self.blob[offset:offset + 16]
                if all(b == 0xFF for b in guid_bytes):
                    # 0xFF padding — end of used space in this volume
                    break
                if all(b == 0x00 for b in guid_bytes):
                    offset += 8
                    continue

                guid_str = self._bytes_to_guid(guid_bytes)

                ffs_type       = self.blob[offset + 18]
                ffs_attributes = self.blob[offset + 19]

                # Size is a 3-byte little-endian integer
                size_bytes = self.blob[offset + 20:offset + 23]
                ffs_size = size_bytes[0] | (size_bytes[1] << 8) | (size_bytes[2] << 16)

                # Sanity check
                if ffs_size < FFS_HEADER_SIZE or offset + ffs_size > end:
                    offset += 8
                    continue

                body_offset = offset + FFS_HEADER_SIZE
                body_size   = ffs_size - FFS_HEADER_SIZE
                body        = self.blob[body_offset:body_offset + body_size]

                self.ffs_files.append({
                    "guid": guid_str,
                    "type": ffs_type,
                    "type_name": self._ffs_type_name(ffs_type),
                    "attributes": ffs_attributes,
                    "offset": offset,
                    "size": ffs_size,
                    "body_offset": body_offset,
                    "body_size": body_size,
                    "body": body,
                    "volume_offset": volume_offset,
                })

                offset += ffs_size

            except (IndexError, struct.error):
                offset += 8

    # ---------------------------------------------------------------- #
    #  Step 3 — Classify Drivers and SMM Modules                        #
    # ---------------------------------------------------------------- #

    def _classify_drivers(self):
        """
        Sort FFS files into DXE drivers and SMM modules.
        SMM modules get double-checked with signature scanning.
        """
        self.drivers     = []
        self.smm_modules = []

        for ffs in self.ffs_files:
            if ffs["type"] in DXE_TYPES:
                self.drivers.append(ffs)

            if ffs["type"] in SMM_TYPES or self._has_smm_signatures(ffs["body"]):
                # Avoid duplicates if type already caught it
                if ffs not in self.smm_modules:
                    self.smm_modules.append(ffs)

    def _has_smm_signatures(self, body: bytes) -> bool:
        """
        Scan driver body for known SMM-related strings.
        A DXE driver that references SMM internals is suspicious.
        """
        return any(sig in body for sig in SMM_SIGNATURES)

    # ---------------------------------------------------------------- #
    #  Helpers                                                           #
    # ---------------------------------------------------------------- #

    def _bytes_to_guid(self, data: bytes) -> str:
        """
        Convert 16 raw bytes to UEFI GUID string format.
        UEFI GUIDs are stored in mixed-endian format:
          Data1 (4 bytes LE), Data2 (2 bytes LE), Data3 (2 bytes LE),
          Data4 (8 bytes BE)
        """
        if len(data) < 16:
            return "00000000-0000-0000-0000-000000000000"

        d1 = struct.unpack_from("<I", data, 0)[0]
        d2 = struct.unpack_from("<H", data, 4)[0]
        d3 = struct.unpack_from("<H", data, 6)[0]
        d4 = data[8:16].hex()

        return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:4].upper()}-{d4[4:].upper()}"

    def _ffs_type_name(self, ffs_type: int) -> str:
        """Human readable FFS type name"""
        names = {
            FFS_TYPE_RAW:            "RAW",
            FFS_TYPE_FREEFORM:       "FREEFORM",
            FFS_TYPE_SECURITY_CORE:  "SEC_CORE",
            FFS_TYPE_PEI_CORE:       "PEI_CORE",
            FFS_TYPE_DXE_CORE:       "DXE_CORE",
            FFS_TYPE_DXE_DRIVER:     "DXE_DRIVER",
            FFS_TYPE_APPLICATION:    "APPLICATION",
            FFS_TYPE_SMM_DRIVER:     "SMM_DRIVER",
        }
        return names.get(ffs_type, f"UNKNOWN(0x{ffs_type:02X})")

    def _driver_summary(self, driver: dict) -> dict:
        """Strip the raw body bytes out before returning to caller"""
        return {k: v for k, v in driver.items() if k != "body"}