#!/usr/bin/env python3
import argparse
from collections import defaultdict
from itertools import count
import os
from ts import TSPacket
from isobmff import SidxBox, SidxReference, StypBox


def index_media_segment(media_file_name, template, force, verbose):
    random_access_points = defaultdict(list)
    if verbose:
        print("Reading media file", media_file_name)
    with open(media_file_name, "rb") as f:
        for byte_offset in count(step=TSPacket.SIZE):
            ts_data = f.read(TSPacket.SIZE)
            if not ts_data:
                break
            ts_packet = TSPacket(ts_data)
            if ts_packet.random_access_indicator:
                if verbose:
                    print("Found TS packet with random_access_indicator = 1 "
                        "at byte offset", byte_offset, "for PID",
                        ts_packet.pid)
                random_access_points[ts_packet.pid].append(byte_offset)

    boxes = [StypBox("sisx")]

    for pid, byte_offsets in random_access_points.items():
        sidx = SidxBox()
        sidx.reference_id = pid
        previous_start = None
        for byte_offset in byte_offsets:
            if previous_start is not None:
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
        choice = input("Output file {} already exists. Overwrite it? y/N" \
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
