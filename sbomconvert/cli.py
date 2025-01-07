# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.generator import SBOMGenerator
from lib4sbom.parser import SBOMParser

from sbomconvert.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbomconvert"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOMconvert transforms a Software Bill of Materials from one format
            to another, or between output formats.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="identity of SBOM",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    # Ensure format is aligned with type of SBOM
    bom_format = args["format"]
    if args["sbom"] == "cyclonedx":
        # Only JSON format valid for CycloneDX
        if bom_format != "json":
            bom_format = "json"

    if args["debug"]:
        print("Input file", args["input_file"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])

    sbom_parser = SBOMParser()
    try:
        sbom_parser.parse_file(args["input_file"])

        sbom_gen = SBOMGenerator(
            sbom_type=args["sbom"],
            format=bom_format,
            application=app_name,
            version=VERSION,
        )

        sbom_gen.generate(
            project_name="",
            sbom_data=sbom_parser.get_sbom(),
            filename=args["output_file"],
        )
    except FileNotFoundError:
        print(f"[ERROR] File '{args['input_file']}' not found.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
