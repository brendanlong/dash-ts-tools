#!/usr/bin/env python3
import argparse

from collections import defaultdict
import os
from ts import *
from isobmff import *


def get_offsets(segment_file_name):
    offsets = defaultdict(list)
    last_pes = {}
    pes_packet = None
    for pes_packet in read_pes(segment_file_name):
        last_pes[pes_packet.pid] = pes_packet
        if pes_packet.random_access:
            logging.debug(
                "Found TS packet with random_access_indicator = 1 at byte "
                "offset %s for PID %s", pes_packet.byte_offset, pes_packet.pid)
            offset = pes_packet.byte_offset, pes_packet.pts
            offsets[pes_packet.pid].append(offset)

    for pid in offsets:
        offset = pes_packet.byte_offset, last_pes[pid].pts
        offsets[pid].append(offset)
    return offsets


def get_segment_indexes(segment_file_name):
    offsets = get_offsets(segment_file_name)

    boxes = []
    for pid, offsets in offsets.items():
        sidx = SidxBox()
        sidx.reference_id = pid
        sidx.first_offset, sidx.earliest_presentation_time = offsets[0]
        previous_start_byte = sidx.first_offset
        previous_start_time = sidx.earliest_presentation_time
        for byte_offset, time_offset in offsets[1:]:
            reference = SidxReference(SidxReference.ReferenceType.MEDIA)
            reference.referenced_size = byte_offset - previous_start_byte
            reference.subsegment_duration = time_offset - previous_start_time
            reference.starts_with_sap = 1
            reference.sap_type = 1
            sidx.references.append(reference)
            previous_start_byte = byte_offset
            previous_start_time = time_offset
        boxes.append(sidx)
    return boxes


def index_media_segment(segment_file_name, template, force):
    boxes = get_segment_indexes(segment_file_name)
    boxes.insert(0, StypBox("sisx"))

    logging.debug("Boxes to write are:")
    for box in boxes:
        logging.debug(box)

    path, file_name = os.path.split(segment_file_name)
    file_name, _ = os.path.splitext(file_name)
    output_file_name = template.format_map(
        {"path": path, "file_name": file_name})
    logging.info("Writing single segment index to %s", output_file_name)
    if not force and os.path.exists(output_file_name):
        choice = input(
            "Output file {} already exists. Overwrite it? [y/N] ".format(
                output_file_name)).lower()
        if choice != 'y':
            return
    with open(output_file_name, "wb") as f:
        for box in boxes:
            f.write(box.bytes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "media_segment", help="The media segment to index.", nargs="*")
    parser.add_argument(
        "--template", "-t", help="Template for segment index files. "
                                 "{file_name} will be replaced with the file "
                                 "name of the media segment minus the suffix "
                                 "(.ts). {path} will be replaced with the "
                                 "full path to the media segment.",
        default="{path}/{file_name}.sidx")
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
    for media_segment in args.media_segment:
        index_media_segment(media_segment, args.template, args.force)
