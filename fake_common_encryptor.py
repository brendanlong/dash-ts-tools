#!/usr/bin/env python3
import argparse
import bitstring
import itertools
import os
import random

from ts import *


class CetsEcmAu(object):
    def __init__(self, initialization_vector):
        self.key_id = None
        self.au_byte_offset = None
        self.initialization_vector = initialization_vector

    @property
    def size(self):
        total = 1 + len(self.initialization_vector)
        if self.key_id is not None:
            total += len(self.key_id)
        if self.au_byte_offset is not None:
            total += len(self.au_byte_offset)
        return total

    @property
    def bytes(self):
        binary = bitstring.pack(
            "bool, pad:3, uint:4",
            self.key_id is not None,
            len(self.au_byte_offset) if self.au_byte_offset is not None else 0)
        if self.key_id is not None:
            binary.append(self.key_id)
        if self.au_byte_offset is not None:
            binary.append(self.au_byte_offset)
        binary.append(self.initialization_vector)
        assert(len(binary) / 8 == self.size)
        return binary.bytes


class CetsEcmState(object):
    def __init__(self, transport_scrambling_control):
        self.transport_scrambling_control = transport_scrambling_control
        self.au = []

    @property
    def size(self):
        total = 1
        for au in self.au:
            total += au.size
        return total

    @property
    def bytes(self):
        binary = bitstring.pack(
            "uint:2, uint:6", self.transport_scrambling_control, len(self.au))
        for au in self.au:
            binary.append(au.bytes)
        assert(len(binary) / 8 == self.size)
        return binary.bytes


class CetsEcm(object):
    def __init__(self, default_key_id):
        self.default_key_id = default_key_id
        self.states = {} # transport_scrambling_control -> state
        self.countdown_sec = None
        self.next_key_id = None

    @property
    def size(self):
        total = 18
        for state in self.states.values():
            total += state.size
        if self.countdown_sec is not None:
            total += 17
        return total

    @property
    def bytes(self):
        iv_size = None
        for state in self.states.values():
            for au in state.au:
                current_iv_size = len(au.initialization_vector)
                if iv_size is None:
                    iv_size = current_iv_size
                elif iv_size != current_iv_size:
                    raise Exception(
                        "Not all IV's are the same size in CETS ECM. "
                        "%s != %s." % (iv_size, current_iv_size))

        binary = bitstring.pack(
            "uint:2, bool, pad:3, uint:8, bytes:16",
            len(self.states), self.countdown_sec is not None, iv_size or 0,
            self.default_key_id)

        for state in self.states.values():
            binary.append(state.bytes)
        if self.countdown_sec is not None:
            binary.append(bitstring.pack(
                "uint:4, uint:4, bytes:16",
                self.countdown_sec, self.next_key_id))
        # Add two bits to make this end at a byte boundary
        # Need to tell MPEG about this
        binary.append(bitstring.pack("pad:2"))
        assert(len(binary) / 8 == self.size)
        return binary.bytes

    def __repr__(self):
        return to_json(self)


def encrypted_ts_packets(media_segment, pcr_pid_start, initialization_segment):
    pcr_pid_generator = itertools.count(pcr_pid_start)
    pmt_pid = None
    pcr_pids = {}
    continuity_counters = {}
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
                    ca_descriptor = Descriptor(Descriptor.TAG_CA_DESCRIPTOR)
                    ca_descriptor.ca_system_id = b"ce"
                    ca_descriptor.ca_pid = pcr_pids[pid]
                    ca_descriptor.scheme_type = 0
                    ca_descriptor.scheme_version = 0
                    ca_descriptor.encryption_algorithm = 0
                    ca_descriptor.systems = []
                    ca_descriptor.private_data_bytes = b""
                    stream.descriptors.append(ca_descriptor)
                ts_packet.payload = pmt.bytes

            elif not ts_packet.random_access_indicator \
                    and ts_packet.pid in pcr_pids:
                scrambling_control = random.randint(1, 3)
                cets_ecm = CetsEcm(b"1234567890123456")
                state = CetsEcmState(scrambling_control)
                au = CetsEcmAu(b"FFFFFFFFFFFFFFFF")
                state.au.append(au)
                cets_ecm.states[scrambling_control] = state

                ecm_ts = TSPacket(pcr_pids[ts_packet.pid])
                ecm_ts.payload = cets_ecm.bytes
                yield ecm_ts

                ts_packet.scrambling_control = scrambling_control
                # Random data looks like encrypted data..
                ts_packet.payload = bytes([random.randint(0, 255)
                                           for i in ts_packet.payload])

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
