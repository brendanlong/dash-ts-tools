#!/usr/bin/env python3
import argparse
import itertools
import os

from ts import *



def encrypted_ts_packets(media_segment, pcr_pid_start, initialization_segment):
    pcr_pid_generator = itertools.count(pcr_pid_start)
    pmt_pid = None
    pcr_pids = {}
    for segment in initialization_segment, media_segment:
        if not segment:
            continue
        for ts_packet in read_ts(segment):
            if ts_packet.pid == ProgramAssociationTable.PID:
                pat = ProgramAssociationTable(ts_packet.payload)
                programs = list(pat.programs.values())
                if len(programs) != 1:
                    raise Exception("PAT has {} programs, but DASH only "
                                    "allows 1 program."
                                    .format(len(pat.programs)))
                if pmt_pid is not None and programs[0] != pmt_pid:
                    raise Exception("PAT has new PMT PID. This program has "
                                    "not been tested to handled this case.")
                pmt_pid = programs[0]

            elif ts_packet.pid == pmt_pid:
                pmt = ProgramMapTable(ts_packet.payload)
                for pid, stream in pmt.streams.items():
                    if pid not in pcr_pids:
                        pcr_pids[pid] = next(pcr_pid_generator)
                    for descriptor in stream.descriptors:
                        if descriptor.tag == Descriptor.TAG_CA_DESCRIPTOR:
                            raise Exception("Stream already has "
                                            "CA_descriptor")
                    ca_descriptor = Descriptor()
                    ca_descriptor.tag = Descriptor.TAG_CA_DESCRIPTOR
                    ca_descriptor.ca_system_id = b"ce"
                    ca_descriptor.ca_pid = pcr_pids[pid]
                    ca_descriptor.scheme_type = 0
                    ca_descriptor.scheme_version = 0
                    ca_descriptor.encryption_algorithm = 0
                    ca_descriptor.systems = []
                    ca_descriptor.private_data_bytes = b""
                    stream.descriptors.append(ca_descriptor)
                ts_packet.payload = pmt.bytes

            elif ts_packet.pid in pcr_pids:
                pcr_pid = pcr_pids[ts_packet.pid]
                # TODO: Encrypt!

            yield ts_packet


def encrypt_segment(media_segment, output_file, pcr_pid_start,
        initialization_segment, force=False):
    logging.info("Reading %s and writing %s" % (media_segment, output_file))
    if os.path.exists(output_file) and not force:
        choice = input(
            "File %s exists, do you want to overwrite it? [y/N] " \
            % (output_file)).lower()
        if choice != "y":
            return
    with open(output_file, "wb") as f:
        for ts_packet in encrypted_ts_packets(media_segment, pcr_pid_start,
                initialization_segment):
            f.write(ts_packet.bytes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "media_segment", help="The media segment to 'encrypt'.", nargs="*")
    parser.add_argument(
        "--initialization_segment", "-i", help="The initialization segment")
    parser.add_argument(
        "--output_directory", "-o", help="Directory to output 'encrypted' "
                                         "segments.",
        default=os.getcwd())
    parser.add_argument(
        "--pcr_pid_start", "-p", help="The first PCR PID. Higher values are "
                                      "also assumed to be usable PCR PIDS.",
        default=300)
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
    for segment in args.media_segment:
        os.makedirs(args.output_directory, exist_ok=True)
        output_file = os.path.join(
            args.output_directory, os.path.basename(segment))
        encrypt_segment(
            segment, output_file, args.pcr_pid_start,
            args.initialization_segment, args.force)
