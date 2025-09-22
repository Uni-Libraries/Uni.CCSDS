#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# Python runner used by the C++ USLP validation harness (subprocess bridge).
# It relies on the vendored IRS spacepackets implementation to encode/decode USLP frames.
#
# Functions:
#   encode: Build a USLP frame from a payload and scenario hints; write frame.bin and tfdf.bin.
#   decode: Parse a USLP frame; write payload.bin and fields.txt with parsed header/TFDF fields.
#
# References:
#   - CCSDS 732.1-B-3 (USLP), esp. §4.1..§4.6 for TFDF construction and managed parameters.
#   - spacepackets.uslp TransferFrame, PrimaryHeader, TransferFrameDataField.

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

# Allow running directly against the vendored source without pip install.
def _prepend_spacepackets_src(p: str) -> None:
    if p and p not in sys.path:
        sys.path.insert(0, p)


def _bool_from_str(s: Optional[str], default: bool) -> bool:
    if s is None:
        return default
    s_lower = s.lower()
    if s_lower in ("1", "true", "yes", "on"):
        return True
    if s_lower in ("0", "false", "no", "off"):
        return False
    return default


def _write_binary(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("wb") as f:
        f.write(data)


def _write_text(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        f.write(text)


def _read_binary(p: Path) -> bytes:
    with p.open("rb") as f:
        return f.read()


def _diag_path(out_dir: Path) -> Path:
    return out_dir / "diag.txt"


def _fields_path(out_dir: Path) -> Path:
    return out_dir / "fields.txt"


def _dump_kv(out_dir: Path, kv: dict) -> None:
    lines = []
    for k, v in kv.items():
        lines.append(f"{k}={v}")
    _write_text(_fields_path(out_dir), "\n".join(lines) + ("\n" if lines else ""))


def _frame_type_from_str(s: Optional[str]) -> Optional["FrameType"]:
    if s is None:
        return None
    sl = s.lower()
    from spacepackets.uslp.frame import FrameType

    if sl in ("fixed", "fp", "fixed_len", "fixed-length"):
        return FrameType.FIXED
    if sl in ("variable", "vp", "var", "variable_len", "variable-length"):
        return FrameType.VARIABLE
    return None


def _select_tfdf_params(upid: int, frame_type_str: Optional[str]) -> Tuple["TfdzConstructionRules", Optional[int], "FrameType"]:
    """
    Provide a sensible default mapping for TFDF construction rules and FHP/LVOP depending on
    the requested frame type and UPID. This can be extended to support more nuanced scenarios.
    """
    from spacepackets.uslp.frame import (
        TfdzConstructionRules,
        FrameType,
        UslpProtocolIdentifier,
    )

    ft = _frame_type_from_str(frame_type_str) or FrameType.VARIABLE
    # Basic defaults:
    # - Variable: No segmentation (single TFDZ), no FHP/LVOP.
    # - Fixed: Packet spanning multiple frames (assume first packet begins at offset 0) -> FHP=0.
    if ft == FrameType.VARIABLE:
        cr = TfdzConstructionRules.VpNoSegmentation
        fhp_lvop = None
    else:
        cr = TfdzConstructionRules.FpPacketSpanningMultipleFrames
        fhp_lvop = 0  # first packet starts at offset 0

    # If explicitly encoding idle data (UPID=IDLE_DATA), still fine: single TFDF, no special pointer.
    if upid == UslpProtocolIdentifier.IDLE_DATA:
        if ft == FrameType.VARIABLE:
            cr = TfdzConstructionRules.VpNoSegmentation
            fhp_lvop = None
        else:
            cr = TfdzConstructionRules.FpPacketSpanningMultipleFrames
            fhp_lvop = 0

    return cr, fhp_lvop, ft


def cmd_encode(args: argparse.Namespace) -> int:
    diag_lines = []
    try:
        _prepend_spacepackets_src(args.spacepackets_src)

        # Imports after path setup
        from spacepackets.uslp.header import (
            PrimaryHeader,
            SourceOrDestField,
            BypassSequenceControlFlag,
            ProtocolCommandFlag,
        )
        from spacepackets.uslp.frame import (
            TransferFrame,
            TransferFrameDataField,
            UslpProtocolIdentifier,
        )

        out_dir = Path(args.out).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        diag = _diag_path(out_dir)

        # Inputs and options
        payload = _read_binary(Path(args.payload))
        scid = int(args.scid) if args.scid is not None else 42
        vcid = int(args.vcid) if args.vcid is not None else 0
        mapid = int(args.mapid) if args.mapid is not None else 0
        upid = int(args.upid) if args.upid is not None else int(UslpProtocolIdentifier.SPACE_PACKETS_ENCAPSULATION_PACKETS)

        has_fecf = _bool_from_str(args.has_fecf, True)

        # Construction rule and frame type defaults
        cr, fhp_lvop, frame_type = _select_tfdf_params(upid=upid, frame_type_str=args.frame_type)

        tfdf = TransferFrameDataField(
            tfdz_cnstr_rules=cr,
            uslp_ident=upid,
            tfdz=payload,
            fhp_or_lvop=fhp_lvop,
        )

        # Build primary header with placeholder frame_len; will be set from content
        ph = PrimaryHeader(
            scid=scid,
            src_dest=SourceOrDestField.SOURCE,
            vcid=vcid,
            map_id=mapid,
            frame_len=0,
            bypass_seq_ctrl_flag=BypassSequenceControlFlag.SEQ_CTRLD_QOS,
            prot_ctrl_cmd_flag=ProtocolCommandFlag.USER_DATA,
            op_ctrl_flag=False,
            vcf_count_len=0,
            vcf_count=None,
        )

        frame = TransferFrame(
            header=ph,
            tfdf=tfdf,
            insert_zone=None,
            op_ctrl_field=None,
            has_fecf=has_fecf,
        )

        # Ensure frame length is reflected into header before packing
        frame.set_frame_len_in_header()

        raw = frame.pack(truncated=False, frame_type=frame_type)
        _write_binary(out_dir / "frame.bin", bytes(raw))
        # Write TFDF as a convenience artifact
        tfdf_bytes = tfdf.pack(truncated=False, frame_type=frame_type)
        _write_binary(out_dir / "tfdf.bin", bytes(tfdf_bytes))

        # Emit some context fields
        _dump_kv(
            out_dir,
            {
                "SCID": str(scid),
                "VCID": str(vcid),
                "MAPID": str(mapid),
                "CR": str(int(cr)),
                "UPID": str(upid),
                "FHP_LVOP": str(fhp_lvop if fhp_lvop is not None else -1),
                "FRAME_TYPE": "FIXED" if str(frame_type).endswith("FIXED") else "VARIABLE",
                "HAS_FECF": "1" if has_fecf else "0",
            },
        )
        _write_text(diag, "encode: ok\n")
        return 0
    except Exception as e:
        try:
            out_dir = Path(args.out).resolve()
            _write_text(_diag_path(out_dir), f"encode: error: {e}\n")
        except Exception:
            pass
        return 1


def _infer_frame_properties(raw: bytes, frame_type: Optional["FrameType"], has_fecf: bool,
                            has_iz: bool, iz_len: int,
                            trunc_len_hint: Optional[int]) -> Tuple["FrameType", object]:
    """
    Determine (or confirm) the frame type and produce the corresponding
    FrameProperties instance required by TransferFrame.unpack.
    """
    from spacepackets.uslp.header import determine_header_type, PrimaryHeader
    from spacepackets.uslp.frame import (
        FrameType,
        FixedFrameProperties,
        VarFrameProperties,
        HeaderType,
    )

    header_type = determine_header_type(raw[0:4])
    # If caller did not specify frame type, assume VARIABLE (safer default)
    ft = frame_type or FrameType.VARIABLE

    # Prepare insert zone presence/size
    present_iz = bool(has_iz and iz_len > 0)
    iz_size = iz_len if present_iz else None

    if ft == FrameType.FIXED:
        # Use the header to determine fixed frame length
        ph = PrimaryHeader.unpack(raw)
        fixed_len = ph.frame_len + 1
        props = FixedFrameProperties(
            fixed_len=fixed_len,
            has_insert_zone=present_iz,
            has_fecf=has_fecf,
            insert_zone_len=iz_size,
        )
        return ft, props
    else:
        # VARIABLE frames: If header is truncated, we must pass truncated_frame_len
        if header_type.name == "TRUNCATED":
            tlen = trunc_len_hint if trunc_len_hint is not None else len(raw)
        else:
            # Not used for non-truncated variable frames, but pass something reasonable
            tlen = len(raw)
        props = VarFrameProperties(
            has_insert_zone=present_iz,
            has_fecf=has_fecf,
            truncated_frame_len=tlen,
            insert_zone_len=iz_size,
        )
        return ft, props


def cmd_decode(args: argparse.Namespace) -> int:
    diag_lines = []
    try:
        _prepend_spacepackets_src(args.spacepackets_src)

        from spacepackets.uslp.header import (
            PrimaryHeader,
            TruncatedPrimaryHeader,
            determine_header_type,
        )
        from spacepackets.uslp.frame import (
            TransferFrame,
            TransferFrameDataField,
            FrameType,
        )

        out_dir = Path(args.out).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        diag = _diag_path(out_dir)

        raw = _read_binary(Path(args.frame))

        ft = _frame_type_from_str(args.frame_type)
        has_fecf = _bool_from_str(args.has_fecf, True)
        has_iz = _bool_from_str(args.iz, False)
        iz_len = int(args.iz_len) if args.iz_len is not None else 0
        trunc_len = int(args.trunc_len) if args.trunc_len is not None else None

        ft, props = _infer_frame_properties(
            raw=raw,
            frame_type=ft,
            has_fecf=has_fecf,
            has_iz=has_iz,
            iz_len=iz_len,
            trunc_len_hint=trunc_len,
        )

        frame = TransferFrame.unpack(raw_frame=raw, frame_type=ft, frame_properties=props)

        # Extract payload (TFDZ)
        payload = bytes(frame.tfdf.tfdz)
        _write_binary(out_dir / "payload.bin", payload)

        # Emit parsed fields for harness checks
        header_type = determine_header_type(raw[0:4])
        if header_type.name == "TRUNCATED":
            ph = TruncatedPrimaryHeader.unpack(raw)
            truncated = 1
            frame_len = len(raw) - 1  # unknown; best effort
        else:
            ph = PrimaryHeader.unpack(raw)
            truncated = 0
            frame_len = ph.frame_len

        kv = {
            "SCID": str(ph.scid),
            "VCID": str(ph.vcid),
            "MAPID": str(ph.map_id),
            "HEADER_TRUNCATED": str(truncated),
            "FRAME_LEN": str(frame_len),
            "CR": str(int(frame.tfdf.tfdz_contr_rules)),
            "UPID": str(int(frame.tfdf.uslp_ident)),
            "FHP_LVOP": str(frame.tfdf.fhp_or_lvop if frame.tfdf.fhp_or_lvop is not None else -1),
            "FRAME_TYPE": "FIXED" if str(ft).endswith("FIXED") else "VARIABLE",
            "HAS_FECF": "1" if has_fecf else "0",
            "HAS_IZ": "1" if has_iz else "0",
            "IZ_LEN": str(iz_len if has_iz else 0),
        }
        _dump_kv(out_dir, kv)
        _write_text(diag, "decode: ok\n")
        return 0
    except Exception as e:
        try:
            out_dir = Path(args.out).resolve()
            _write_text(_diag_path(out_dir), f"decode: error: {e}\n")
        except Exception:
            pass
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="USLP validation harness Python runner (spacepackets bridge)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--spacepackets-src", required=True, help="Path to spacepackets-py/src")
    common.add_argument("--out", required=True, help="Output directory for artifacts")

    # encode
    pe = sub.add_parser("encode", parents=[common], help="Encode a USLP frame from payload")
    pe.add_argument("--payload", required=True, help="Path to payload binary")
    pe.add_argument("--scid", required=False, help="Spacecraft ID (16-bit)")
    pe.add_argument("--vcid", required=False, help="Virtual Channel ID (6-bit)")
    pe.add_argument("--mapid", required=False, help="MAP ID (4-bit)")
    pe.add_argument("--upid", required=False, help="USLP Protocol ID (5-bit)")
    pe.add_argument("--frame-type", required=False, help="fixed|variable")
    pe.add_argument("--has-fecf", required=False, help="true|false (default: true)")

    # decode
    pd = sub.add_parser("decode", parents=[common], help="Decode a USLP frame")
    pd.add_argument("--frame", required=True, help="Path to frame binary")
    pd.add_argument("--frame-type", required=False, help="fixed|variable (optional hint)")
    pd.add_argument("--has-fecf", required=False, help="true|false (default: true)")
    pd.add_argument("--iz", required=False, help="true|false (insert zone present, default: false)")
    pd.add_argument("--iz-len", required=False, help="insert zone length (bytes) when iz=true")
    pd.add_argument("--trunc-len", required=False, help="truncated frame total length (bytes) hint for variable frames")

    return p


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "encode":
        return cmd_encode(args)
    elif args.cmd == "decode":
        return cmd_decode(args)
    else:
        print(f"Unknown subcommand: {args.cmd}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))