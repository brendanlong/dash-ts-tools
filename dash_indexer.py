#!/usr/bin/env python3
import argparse
from collections import defaultdict
import logging
import os
from ts import *
from isobmff import *


def get_offsets(media_file_name):
    byte_offsets = defaultdict(list)
    for pes_packet in read_pes(media_file_name):
        if pes_packet.random_access:
            logging.debug("Found TS packet with "
                "random_access_indicator = 1 at byte offset %s for "
                "PID %s", pes_packet.byte_offset, pes_packet.pid)
            byte_offsets[pes_packet.pid].append(pes_packet.byte_offset)

    for pid in byte_offsets:
        byte_offsets[pid].append(pes_packet.byte_offset + pes_packet.size)
    print(dict(byte_offsets))
    return byte_offsets


def index_media_segment(media_file_name, template, force):
    byte_offsets = get_offsets(media_file_name)

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

    logging.debug("Boxes to write are:")
    for box in boxes:
        logging.debug(box)

    segment_prefix, _ = os.path.splitext(media_file_name)
    output_file_name = template.format_map({"s": segment_prefix})
    logging.debug("Writing single segment index to %s", output_file_name)
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
    logging.basicConfig(format='%(levelname)s: %(message)s',
        level=logging.DEBUG if args.verbose else logging.INFO)
    index_media_segment(args.media_segment, args.template, args.force)
