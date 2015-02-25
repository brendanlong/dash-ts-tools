#!/usr/bin/env python3
import argparse
import os

from collections import defaultdict
from enum import Enum
from ts import *
from isobmff import *


def get_offsets(segment_file_name):
    offsets = defaultdict(list)
    last_pts = {}
    pes_packet = None
    for pes_packet in read_pes(segment_file_name):
        if not pes_packet.pts:
            continue
        last_pts[pes_packet.pid] = max(
            pes_packet.pts, last_pts.get(pes_packet.pid, pes_packet.pts))
        if pes_packet.random_access:
            logging.debug(
                "Found TS packet with random_access_indicator = 1 at byte "
                "offset %s for PID %s", pes_packet.byte_offset, pes_packet.pid)
            offset = pes_packet.byte_offset, pes_packet.pts
            offsets[pes_packet.pid].append(offset)

    for pid in offsets:
        offset = pes_packet.byte_offset, last_pts[pid]
        offsets[pid].append(offset)
    return offsets


def get_segment_indexes(segment_file_name):
    logging.info("Generating segment index for %s", segment_file_name)
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


class IndexType(Enum):
    SINGLE_SEGMENT_INDEX = 1
    REPRESENTATION_INDEX = 2

    @staticmethod
    def from_string(s):
        return {
            "single": IndexType.SINGLE_SEGMENT_INDEX,
            "representation": IndexType.REPRESENTATION_INDEX
        }[s]


def write_boxes(segment_file_name, name_part, template, boxes, force):
        path, file_name = os.path.split(segment_file_name)
        if name_part is None:
            name_part, _ = os.path.splitext(file_name)
        output_file_name = template.format_map(
            {"path": path, "name_part": name_part})
        logging.info("Writing index to %s", output_file_name)

        if not force and os.path.exists(output_file_name):
            choice = input(
                "Output file {} already exists. Overwrite it? "
                "[y/N] ".format(
                    output_file_name)).lower()
            if choice != 'y':
                return
        with open(output_file_name, "wb") as f:
            for box in boxes:
                f.write(box.bytes)


def index_media_segments(segment_file_names, template, index_type, force):
    indexes = {file_name: get_segment_indexes(file_name)
               for file_name in segment_file_names}

    logging.debug("Boxes to write are:")
    for file_name, boxes in indexes.items():
        logging.debug(file_name)
        for box in boxes:
            logging.debug(box)
        logging.debug("")

    in_order = list(indexes.items())
    in_order.sort(key=lambda x: x[1][0].earliest_presentation_time)
    if index_type == IndexType.SINGLE_SEGMENT_INDEX:
        for file_name, boxes in in_order:
            boxes.insert(0, StypBox("sisx"))
            write_boxes(file_name, None, template, boxes, force)
    else:
        # TODO: This code won't work if there's more than one PID to index
        index_sidx = SidxBox()
        first_sidx = in_order[0][1][0]
        index_sidx.reference_id = first_sidx.reference_id
        index_sidx.earliest_presentation_time = \
            first_sidx.earliest_presentation_time
        index_sidx.first_offset = 0

        boxes = [StypBox("risx"), index_sidx]

        for _, segment_boxes in in_order:
            sidx = segment_boxes[0]
            reference = SidxReference(SidxReference.ReferenceType.INDEX)
            reference.subsegment_duration = sidx.duration
            reference.referenced_size = sidx.size
            index_sidx.references.append(reference)

        for _, segment_boxes in in_order:
            boxes.extend(segment_boxes)
        write_boxes(
            segment_file_names[0], "representation", template, boxes, force)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "media_segment", help="The media segment to index.", nargs="*")
    parser.add_argument(
        "--template", "-t", help="Template for segment index files. "
                                 "{name_part} will be replaced with the file "
                                 "name of the media segment minus the suffix "
                                 "(.ts). {path} will be replaced with the "
                                 "full path to the media segment. For "
                                 "representation index, {name_part} will be "
                                 "'representation' and {path} will come from "
                                 "the first listed segment.",
        default="{path}/{name_part}.sidx")
    parser.add_argument(
        "--index-type", "-i", type=IndexType.from_string,
        default=IndexType.SINGLE_SEGMENT_INDEX, help="The type of ")
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
    index_media_segments(
        args.media_segment, args.template, args.index_type, args.force)
