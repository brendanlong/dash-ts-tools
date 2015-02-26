#!/usr/bin/env python3
import argparse
import os

from ts import *


def write_ts(file_name, packets, force):
    logging.info("Writing %s", file_name)

    if not force and os.path.exists(file_name):
        choice = input(
            "Output file {} already exists. Overwrite it? "
            "[y/N] ".format(file_name)).lower()
        if choice != "y":
            return
    with open(file_name, "wb") as f:
        for packet in packets:
            f.write(packet.bytes)


def generate_initialization_segment(
        segment_file_names, segment_template, out_file_name, force):
    pat = None
    pat_ts = None
    pmt = None
    pmt_ts = None
    segment_ts = {}
    pmt_pid = None
    for segment_file_name in segment_file_names:
        current_segment_ts = []
        segment_ts[segment_file_name] = current_segment_ts
        for ts in read_ts(segment_file_name):
            if ts.pid == ProgramAssociationTable.PID:
                new_pat = ProgramAssociationTable(ts.payload)
                if pat is None:
                    pat = new_pat
                    pat_ts = ts
                    programs = list(pat.programs.values())
                    if len(programs) != 1:
                        raise Exception(
                            "PAT has {} programs, but DASH only allows 1 "
                            "program.".format(len(pat.programs)))
                    if pmt_pid is not None and programs[0] != pmt_pid:
                        raise Exception("PAT has new PMT PID. This program has "
                                        "not been tested to handled this case.")
                    pmt_pid = programs[0]
                elif new_pat != pat:
                    raise Exception("Cannot generate initialization segment "
                                    "for segment with multiple PAT's. {} != {"
                                    "}".format(new_pat, pat))
            elif ts.pid == pmt_pid:
                new_pmt = ProgramMapTable(ts.payload)
                if pmt is None:
                    pmt = new_pmt
                    pmt_ts = ts
                elif new_pmt != pmt:
                    raise Exception("Cannot generate initialization segment "
                                    "for segment with multiple PMT's. {} != {"
                                    "}".format(new_pmt, pmt))
            else:
                current_segment_ts.append(ts)

    logging.debug("Common PSI is:\nPAT: %s\nPMT: %s", pat, pmt)
    write_ts(out_file_name, [pat_ts, pmt_ts], force)
    for segment_file_name in segment_file_names:
        path, file_name = os.path.split(segment_file_name)
        name_part, _ = os.path.splitext(file_name)
        segment_out_file_name = segment_template.format_map(
            {"path": path, "name_part": name_part})
        write_ts(segment_out_file_name, segment_ts[segment_file_name], force)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "media_segment", nargs="+",
        help="The media segments to create an initialization segment for.")
    parser.add_argument(
        "--segment-template", "-s",
        help="Template for segment index files. {name_part} will be replaced "
             "with the file name of the media segment minus the suffix (.ts). "
             "{path} will be replaced with the full path to the media segment.",
        default="{path}/{name_part}.sidx")
    parser.add_argument(
        "--out", "-o", required=True,
        help="The file to write the initialization segment to.")
    parser.add_argument(
        "--force", "-f", action="store_true", default=False,
        help="Overwrite output files without prompting.")
    parser.add_argument(
        "--verbose", "-v", action="store_true", default=False,
        help="Enable verbose output.")

    args = parser.parse_args()
    logging.basicConfig(
        format='%(levelname)s: %(message)s',
        level=logging.DEBUG if args.verbose else logging.INFO)
    generate_initialization_segment(
        args.media_segment, args.segment_template, args.out, args.force)
