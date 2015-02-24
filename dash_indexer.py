#!/usr/bin/env python3
import argparse
from collections import defaultdict
from itertools import count
import os
from ts import PESReader, ProgramAssociationTable, ProgramMapTable, TSPacket
from isobmff import SidxBox, SidxReference, StypBox


def get_offsets(media_file_name, verbose):
    byte_offsets = defaultdict(list)
    with open(media_file_name, "rb") as f:
        pmt_pid = None
        pes_readers = {}
        for byte_offset in count(step=TSPacket.SIZE):
            ts_data = f.read(TSPacket.SIZE)
            if not ts_data:
                for pid in byte_offsets:
                    byte_offsets[pid].append(byte_offset)
                break
            ts_packet = TSPacket(ts_data)

            if ts_packet.pid == ProgramAssociationTable.PID:
                pat = ProgramAssociationTable(ts_packet.payload)
                programs = list(pat.programs.values())
                if len(programs) != 1:
                    raise Exception("PAT has {} programs, but DASH only "
                        "allows 1 program.".format(len(pat.programs)))
                if pmt_pid is not None and programs[0] != pmt_pid:
                    raise Exception("PAT has new PMT PID. This program has "
                        "not been tested to handled this case.")
                pmt_pid = programs[0]

            elif ts_packet.pid == pmt_pid:
                pmt = ProgramMapTable(ts_packet.payload)
                for pid in pmt.streams:
                    if pid not in pes_readers:
                        pes_readers[pid] = PESReader(verbose)

            elif ts_packet.pid in pes_readers:
                pes_packet = pes_readers[ts_packet.pid].add_ts_packet(ts_packet)
                if pes_packet:
                    pass

                if ts_packet.random_access_indicator:
                    if verbose:
                        print("Found TS packet with random_access_indicator = "
                            "1 at byte offset", byte_offset, "for PID",
                            ts_packet.pid)
                    byte_offsets[ts_packet.pid].append(byte_offset)
    return byte_offsets


def index_media_segment(media_file_name, template, force, verbose):
    if verbose:
        print("Reading media file", media_file_name)
    byte_offsets = get_offsets(media_file_name, verbose)

    boxes = [StypBox("sisx")]

    for pid, byte_offsets in byte_offsets.items():
        sidx = SidxBox()
        sidx.reference_id = pid
        sidx.first_offset = byte_offsets[0]
        previous_start = sidx.first_offset
        for byte_offset in byte_offsets[1:]:
            reference = SidxReference(SidxReference.ReferenceType.MEDIA)
            reference.referenced_size = byte_offset - previous_start
            sidx.references.append(reference)
            previous_start = byte_offset
        boxes.append(sidx)

    if verbose:
        print("Boxes to write are:")
        for box in boxes:
            print(box)

    segment_prefix, _ = os.path.splitext(media_file_name)
    output_file_name = template.format_map({"s": segment_prefix})
    if verbose:
        print("Writing single segment index to", output_file_name)
    if not force and os.path.exists(output_file_name):
        choice = input("Output file {} already exists. Overwrite it? [y/N] " \
            .format(output_file_name)).lower()
        if choice != 'y':
            return
    with open(output_file_name, "wb") as f:
        for box in boxes:
            f.write(box.bytes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("media_segment", help="The media segment to index.")
    parser.add_argument("--template", "-t", help="Template for segment index "
        "files. {s} will be replaced with the name of the media segment minus "
        "the suffix (.ts).",
        default="{s}.sidx")
    parser.add_argument("--force", "-f", action="store_true", default=False,
        help="Overwrite output files without prompting.")
    parser.add_argument("--verbose", "-v", action="store_true", default=False,
        help="Enable verbose output.")

    args = parser.parse_args()
    index_media_segment(args.media_segment, args.template, args.force,
        args.verbose)
