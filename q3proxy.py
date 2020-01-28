#!/usr/bin/env python3

# Jacek Fedorynski <jfedor@jfedor.org>
# https://github.com/jfedor2/quake3-proxy-aimbot

import socket
import select
import collections
import time
import random
import struct
import math
import argparse
import traceback
import sys

import huffman
import buffers
import defs

Task = collections.namedtuple("Task", ["time", "task"])
Fragments = collections.namedtuple("Fragments", ["start", "data"])
Snapshot = collections.namedtuple("Snapshot", ["sequence", "playerstate", "entities"])


def create_send_task(socket_, data, time_, drop_probability, address):
    my_data = data[:]

    def task():
        if random.random() < drop_probability:
            return
        socket_.sendto(my_data, address)

    return Task(time=time_, task=task)


def hash_string(string, max_len):
    hash_ = 0
    for i in range(max_len):
        if i >= len(string) or string[i] == 0:
            break
        hash_ += string[i] * (119 + i)
    hash_ = hash_ & (2**32 - 1)
    hash_ = (hash_ ^ (hash_ >> 10) ^ (hash_ >> 20))
    return hash_


def address_to_bytes(address):
    return socket.inet_aton(address[0]) + struct.pack('!H', address[1])


def look_at(player_position, target_position):
    offsets = tuple(target_position[i] - player_position[i] for i in range(3))
    return (-math.atan2(offsets[2], math.sqrt(offsets[1]**2 + offsets[0]**2)),
            math.atan2(offsets[1], offsets[0]), 0)


def modulo_distance(x, y, mod):
    distance = abs(x - y)
    return min(distance, mod - distance)


def angle_distance(angle1, angle2):
    return math.sqrt(sum(modulo_distance(angle1[i], angle2[i], 65536)**2 for i in range(2)))


def select_target_angles(player_angles, potential_targets, threshold):
    min_distance = threshold * 65536 / 360 if threshold is not None else None
    angles = player_angles
    for target in potential_targets:
        distance = angle_distance(player_angles[0:2], target[0:2])
        if min_distance is None or distance < min_distance:
            min_distance = distance
            angles = list(target)
    return angles


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-address", help="server address to connect to")
    parser.add_argument(
        "--server-port",
        type=int,
        default=27960,
        help="server port to connect to, %(default)s by default")
    parser.add_argument("--listen-port", type=int, help="port to listen on")
    parser.add_argument("--socks-port", type=int, help="SOCKS proxy port to listen on")
    parser.add_argument(
        "--socks-public-address", help="public address to give to SOCKS proxy clients")
    parser.add_argument(
        "--client-to-server-delay",
        type=int,
        default=0,
        metavar="MILLISECONDS",
        help="simulated network latency for client-to-server packets")
    parser.add_argument(
        "--server-to-client-delay",
        type=int,
        default=0,
        metavar="MILLISECONDS",
        help="simulated network latency for server-to-client packets")
    parser.add_argument(
        "--client-to-server-packet-loss",
        type=int,
        default=0,
        metavar="PERCENT",
        help="simulated packet loss for client-to-server packets")
    parser.add_argument(
        "--server-to-client-packet-loss",
        type=int,
        default=0,
        metavar="PERCENT",
        help="simulated packet loss for server-to-client packets")
    parser.add_argument("--aimbot", action="store_true", help="enable aimbot")
    parser.add_argument(
        "--aimbot-fov",
        type=int,
        metavar="FOV",
        help="only auto-aim at targets within a cone this wide around the crosshair")
    parser.add_argument(
        "--read-dump",
        metavar="FILE",
        help="read and process a tcpdump/wireshark *.pcap file instead of doing live traffic")
    parser.add_argument(
        "--print-packets-as-html",
        action="store_true",
        help="print the processed contents of all packets as HTML")
    parser.add_argument(
        "--dont-print-exceptions",
        action="store_false",
        dest="print_exceptions",
        help="suppress printing exceptions that occur during traffic processing")
    parser.add_argument(
        "--debug-level",
        type=int,
        default=1,
        help="verbosity, 2 prints something for every packet, default: 1")

    return parser.parse_args()


def validate_arguments(config):
    if not config.listen_port and not config.read_dump:
        print("Either --listen-port or --read-dump must be specified.")
        return False

    if config.read_dump and not config.server_address:
        print("If --read-dump is specified then --server-address must also be specified.")
        return False

    if config.listen_port and not config.server_address and not config.socks_port:
        print("If --listen-port is specified then either --server-address"
              " or --socks-port must also be specified.")
        return False

    if config.socks_port and not config.socks_public_address:
        print("If --socks-port is specified then --socks-public-address must also be specified.")
        return False

    return True


class Trace:

    def __init__(self):
        self.trace_stack = [[]]
        self.name_stack = []

    def add(self, name, value):
        if name is None:
            return
        self.trace_stack[-1].append((name, value))

    def begin(self, name):
        self.trace_stack.append([])
        self.name_stack.append(name)

    def end(self):
        block = self.trace_stack.pop()
        name = self.name_stack.pop()
        self.add(name, block)

    def get_as_html(self, trace=None):
        output = "<div>"
        if trace is None:
            trace = self.trace_stack[0]
        for t in trace:
            if isinstance(t[1], list):
                output += self.get_as_html(t[1])
            else:
                output += "<p>{}: {}</p>".format(t[0], t[1])
        output += "</div>"
        return output


class Client:

    def __init__(self, client_address, server_socket, config):
        self.client_address = client_address
        self.server_socket = server_socket
        self.config = config
        self.last_active = None
        self.clear_data()

    def clear_data(self):
        self.fragments = {}
        self.challenge = None
        self.checksum_feed = None
        self.client_commands = [b'\0'] * defs.MAX_RELIABLE_COMMANDS
        self.server_commands = [b'\0'] * defs.MAX_RELIABLE_COMMANDS
        self.snapshots = [None] * defs.PACKET_BACKUP
        self.baselines = {}
        self.potential_targets = None
        self.protocol = 'quake3'

    def process_server_packet(self, data, trace):
        (raw_sequence,) = struct.unpack_from('<I', data)
        trace.add("sequence", raw_sequence)
        if raw_sequence == 0xffffffff:
            trace.add("command", '"' + data[4:].decode('ascii', errors='backslashreplace') + '"')
            if data[4:].startswith(b'challengeResponse '):
                self.clear_data()  # need this if we're reconnecting to the same server
                self.challenge = int(data[4:].lstrip(b'challengeResponse ').split(b' ')[0])
        else:
            actual_data, sequence = self.handle_fragments(data)
            if not actual_data:
                return

            if not self.challenge:
                if self.config.debug_level >= 2:
                    print("Looks like we didn't see the connection from the "
                          "beginning. Can't inspect the packets so falling back "
                          "to dumb proxy mode.")
                return

            buffer = buffers.Buffer(actual_data, trace)

            reliable_acknowledge = buffer.read_bits(32, "reliable_acknowledge")
            last_command = self.client_commands[reliable_acknowledge &
                                                (defs.MAX_RELIABLE_COMMANDS - 1)]
            key = self.challenge ^ sequence

            buffer.xor(4, key, last_command)

            stop = False
            while not stop:
                trace.begin("_command")
                svc_op = buffer.read_bits(8, "svc_op")
                if svc_op == 8:  # svc_EOF
                    stop = True
                elif svc_op == 2:  # svc_gamestate
                    self.parse_gamestate(buffer, trace)
                elif svc_op == 5:  # svc_serverCommand
                    command_sequence = buffer.read_bits(32, "command_sequence")
                    command = buffer.read_string("command")
                    self.server_commands[command_sequence &
                                         (defs.MAX_RELIABLE_COMMANDS - 1)] = command
                elif svc_op == 6:  # svc_download
                    self.parse_download(buffer, trace)
                elif svc_op == 7:  # svc_snapshot
                    snapshot = self.parse_snapshot(buffer, sequence, trace)
                    self.snapshots[sequence & defs.PACKET_MASK] = snapshot
                    if self.config.aimbot:
                        self.aimbot(snapshot.playerstate, snapshot.entities)
                else:
                    raise Exception("unknown svc_op: {}".format(svc_op))
                    #break
                trace.end()

    def process_client_packet(self, data, trace):
        (sequence,) = struct.unpack_from('<I', data)
        trace.add("sequence", sequence)
        if sequence == 0xffffffff:
            if data[4:12] == b'connect ':
                trace.add("command", '"connect "')
                (userinfo_length,) = struct.unpack_from('>H', data, 12)
                huff = huffman.Huffman()
                userinfo_string = huff.decode(buffers.Buffer(data[14:]), userinfo_length)
                trace.add("userinfo",
                          '"' + userinfo_string.decode('ascii', errors='backslashreplace') + '"')
                userinfo_list = userinfo_string.strip(b'"').split(b'\\')[1:]
                userinfo = dict(zip(*[userinfo_list[i::2] for i in range(2)]))
                if userinfo[b'protocol'] == b'68':
                    self.protocol = 'quake3'
                elif userinfo[b'protocol'] == b'91':
                    self.protocol = 'quakelive'
                else:
                    if self.config.debug_level >= 1:
                        print("Unknown protocol: {}, proceeding as if 68.".format(
                            userinfo[b'protocol'].decode('ascii', errors='backslashreplace')))
            else:
                trace.add("command",
                          '"' + data[4:].decode('ascii', errors='backslashreplace') + '"')
            encoded_data = data
        else:
            if not self.challenge or not self.checksum_feed:
                if self.config.debug_level >= 2:
                    print("Looks like we didn't see the connection from the "
                          "beginning. Can't inspect the packets so falling back "
                          "to dumb proxy mode.")
                return data
            (qport,) = struct.unpack_from('<H', data, 4)
            trace.add("qport", qport)
            buffer = buffers.Buffer(data[6:], trace)
            output = buffers.Buffer() if self.config.aimbot else None
            server_id = buffer.read_bits(32, "server_id", passthru=output)
            server_message_sequence = buffer.read_bits(
                32, "server_message_sequence", passthru=output)  # messageAcknowledge
            server_command_sequence = buffer.read_bits(
                32, "server_command_sequence", passthru=output)  # reliable_acknowledge

            last_command = self.server_commands[server_command_sequence &
                                                (defs.MAX_RELIABLE_COMMANDS - 1)]
            key = self.challenge ^ server_id ^ server_message_sequence
            buffer.xor(12, key, last_command)

            if self.protocol == 'quakelive':
                buffer.read_bits(8, "unknown", passthru=output)

            stop = False
            while not stop:
                trace.begin("_clc_op")
                clc_op = buffer.read_bits(8, "clc_op", passthru=output)
                if clc_op == 5:  # clc_EOF
                    stop = True
                elif clc_op == 4:  # clc_clientCommand
                    command_sequence = buffer.read_bits(32, "command_sequence", passthru=output)
                    command = buffer.read_string("command", passthru=output)
                    self.client_commands[command_sequence &
                                         (defs.MAX_RELIABLE_COMMANDS - 1)] = command
                elif clc_op in [2, 3]:  # clc_move, clc_moveNoDelta
                    partial_key = (
                        self.checksum_feed ^ server_message_sequence ^
                        hash_string(last_command, 32))
                    self.process_usercmds(buffer, output, partial_key, trace)
                else:
                    raise Exception("unknown clc_op {}".format(clc_op))
                    #break
                trace.end()

            if self.config.aimbot:
                output.xor(12, key, last_command)
                encoded_data = data[0:6] + output.data
            else:
                encoded_data = data

        return encoded_data

    def handle_fragments(self, data):
        (sequence,) = struct.unpack_from('<I', data)
        if sequence & defs.FRAGMENT_BIT:
            sequence &= ~defs.FRAGMENT_BIT
            (fragment_start,) = struct.unpack_from('<H', data, 4)
            (fragment_length,) = struct.unpack_from('<H', data, 6)
            if self.config.debug_level >= 2:
                print("Fragment received, sequence: {}, fragment_start: {}, fragment_length: {}.".
                      format(sequence, fragment_start, fragment_length))
            if sequence not in self.fragments:
                self.fragments[sequence] = Fragments(start=0, data=b'')
            if fragment_start == self.fragments[sequence].start:
                self.fragments[sequence] = Fragments(
                    start=self.fragments[sequence].start + fragment_length,
                    data=self.fragments[sequence].data + data[8:])
            else:
                if self.config.debug_level >= 2:
                    print("Fragment dropped or out of order?")
                return None, None
            if fragment_length != defs.FRAGMENT_SIZE:
                if self.config.debug_level >= 2:
                    print("Fragments assembled.")
                assembled_data = self.fragments[sequence].data
                del self.fragments[sequence]
                return assembled_data, sequence
            else:
                if self.config.debug_level >= 2:
                    print("Not final fragment.")
                return None, None
        else:
            return data[4:], sequence

    def process_usercmds(self, buffer, output, partial_key, trace):
        command_count = buffer.read_bits(8, "command_count", passthru=output)
        server_time = 0
        oldcmd = UserCommand()
        for _ in range(command_count):
            trace.begin("_usercmd")
            if buffer.read_bit("server_time_relative", passthru=output):
                server_time_delta = buffer.read_bits(8, "server_time_delta", passthru=output)
                server_time += server_time_delta
            else:
                server_time = buffer.read_bits(32, "server_time", passthru=output)
            if buffer.read_bit("command_changed", passthru=output):
                key = partial_key ^ server_time
                cmd = UserCommand()
                cmd.angles[0] = buffer.read_delta_key(16, oldcmd.angles[0], key, "angles[0]")
                cmd.angles[1] = buffer.read_delta_key(16, oldcmd.angles[1], key, "angles[1]")
                cmd.angles[2] = buffer.read_delta_key(16, oldcmd.angles[2], key, "angles[2]")
                cmd.forwardmove = buffer.read_delta_key(8, oldcmd.forwardmove, key, "forwardmove")
                cmd.rightmove = buffer.read_delta_key(8, oldcmd.rightmove, key, "rightmove")
                cmd.upmove = buffer.read_delta_key(8, oldcmd.upmove, key, "upmove")
                cmd.buttons = buffer.read_delta_key(16, oldcmd.buttons, key, "buttons")
                cmd.weapon = buffer.read_delta_key(8, oldcmd.weapon, key, "weapon")

                if self.protocol == 'quakelive':
                    cmd.unknown1 = buffer.read_delta_key(8, 0, key, "unknown1")
                    cmd.unknown2 = buffer.read_delta_key(8, 0, key, "unknown2")

                if (cmd.buttons & 1 and self.potential_targets and cmd.weapon in [2, 3, 6, 7]):
                    if self.config.debug_level >= 2:
                        print("Aiming.")
                    cmd.angles = select_target_angles(
                        cmd.angles, self.potential_targets,
                        self.config.aimbot_fov / 2 if self.config.aimbot_fov is not None else None)
                if output:
                    output.write_delta_key(cmd.angles[0], oldcmd.angles[0], 16, key)
                    output.write_delta_key(cmd.angles[1], oldcmd.angles[1], 16, key)
                    output.write_delta_key(cmd.angles[2], oldcmd.angles[2], 16, key)
                    output.write_delta_key(cmd.forwardmove, oldcmd.forwardmove, 8, key)
                    output.write_delta_key(cmd.rightmove, oldcmd.rightmove, 8, key)
                    output.write_delta_key(cmd.upmove, oldcmd.upmove, 8, key)
                    output.write_delta_key(cmd.buttons, oldcmd.buttons, 16, key)
                    output.write_delta_key(cmd.weapon, oldcmd.weapon, 8, key)

                    if self.protocol == 'quakelive':
                        output.write_delta_key(cmd.unknown1, oldcmd.unknown1, 8, key)
                        output.write_delta_key(cmd.unknown2, oldcmd.unknown2, 8, key)

                oldcmd = cmd
            trace.end()

    def aimbot(self, playerstate, entities):
        self.potential_targets = []
        player_position = tuple(playerstate.get('origin[{}]'.format(i)) for i in range(3))
        if None in player_position:
            return
        delta_angles = tuple(playerstate.get('delta_angles[{}]'.format(i), 0) for i in range(3))
        for entity in entities.values():
            if (entity.get('eType') == 1 and entity.get('eFlags', 0) & 1 == 0):
                target_position = tuple(entity.get('pos.trBase[{}]'.format(i)) for i in range(3))
                if None in target_position:
                    continue
                target_angles = look_at(player_position, target_position)
                aimbot_angles = tuple(
                    int(32768 / math.pi * target_angles[i] - delta_angles[i]) & 0xffff
                    for i in range(3))
                self.potential_targets.append(aimbot_angles)

    def parse_snapshot(self, buffer, sequence, trace):
        server_time = buffer.read_bits(32, "server_time")
        delta_num = buffer.read_bits(8, "delta_num")

        snapshot_to_delta_from = (None if delta_num == 0 else
                                  self.snapshots[(sequence - delta_num) & defs.PACKET_MASK])

        if snapshot_to_delta_from and snapshot_to_delta_from.sequence != sequence - delta_num:
            if self.config.debug_level >= 2:
                print("We no longer have the snapshot that we want to delta from.")
            snapshot_to_delta_from = None

        buffer.read_bits(8, "snap_flags")
        trace.begin("_areamask")
        areamask_length = buffer.read_bits(8, "areamask_length")
        buffer.read_bits(areamask_length * 8, "areamask")
        trace.end()

        playerstate = self.parse_playerstate(buffer, snapshot_to_delta_from, trace)
        entities = self.parse_entities(buffer, snapshot_to_delta_from, trace)

        return Snapshot(sequence=sequence, playerstate=playerstate, entities=entities)

    def parse_playerstate(self, buffer, snapshot_to_delta_from, trace):
        trace.begin("_playerstate")
        if snapshot_to_delta_from is not None:
            playerstate = snapshot_to_delta_from.playerstate.copy()
        else:
            playerstate = {}
        field_count = buffer.read_bits(8, "field_count")
        for i in range(field_count):
            trace.begin("_field")
            if buffer.read_bit("field_changed"):
                field = defs.PLAYERSTATE_FIELDS[self.protocol][i]
                if field.bits == 0:  # float
                    if buffer.read_bit("int_or_float") == 0:
                        playerstate[field.name] = buffer.read_int_float(field.name)
                    else:
                        playerstate[field.name] = buffer.read_float(field.name)
                else:
                    playerstate[field.name] = buffer.read_bits(field.bits, field.name)
            trace.end()
        if buffer.read_bit("arrays_changed"):
            trace.begin("_stats")
            if buffer.read_bit("stats_changed"):
                bits = buffer.read_bits(16, "stats_bits")
                for i in range(16):
                    if bits & (1 << i):
                        buffer.read_bits(16, "stats_bit_{}".format(i))
            trace.end()
            trace.begin("_persistant")
            if buffer.read_bit("persistant_changed"):
                bits = buffer.read_bits(16, "persistant_bits")
                for i in range(16):
                    if bits & (1 << i):
                        buffer.read_bits(16, "persistant_bit_{}".format(i))
            trace.end()
            trace.begin("_ammo")
            if buffer.read_bit("ammo_changed"):
                bits = buffer.read_bits(16, "ammo_bits")
                for i in range(16):
                    if bits & (1 << i):
                        buffer.read_bits(16, "ammo_bit_{}".format(i))
            trace.end()
            trace.begin("_powerups")
            if buffer.read_bit("powerups_changed"):
                bits = buffer.read_bits(16, "powerups_bits")
                for i in range(16):
                    if bits & (1 << i):
                        buffer.read_bits(32, "powerup_bit_{}".format(i))
            trace.end()

        trace.end()
        return playerstate

    def parse_entities(self, buffer, snapshot_to_delta_from, trace):
        trace.begin("_entities")
        if snapshot_to_delta_from is not None:
            entities = snapshot_to_delta_from.entities.copy()
        else:
            entities = {}
        stop = False
        while not stop:
            trace.begin("_entity")
            entity_number = buffer.read_bits(defs.GENTITYNUM_BITS, "entity_number")
            if entity_number == defs.MAX_GENTITIES - 1:
                stop = True
            elif buffer.read_bit("update_or_delete") == 1:
                if entity_number in entities:
                    del entities[entity_number]
                else:
                    if self.config.debug_level >= 2:
                        print('Deleted entity not present ({})?'.format(entity_number))
            else:
                if entity_number in entities:
                    old = entities[entity_number]
                else:
                    if entity_number in self.baselines:
                        old = self.baselines[entity_number]
                    else:
                        if self.config.debug_level >= 3:
                            print("Delta from nonexistent baseline?")
                        old = {}
                entities[entity_number] = self.read_delta_entity(buffer, old, trace)
            trace.end()

        trace.end()
        return entities

    def parse_gamestate(self, buffer, trace):
        self.baselines = {}
        server_command_sequence = buffer.read_bits(32, "server_command_sequence")
        stop = False
        while not stop:
            trace.begin("_gamestate_op")
            gamestate_op = buffer.read_bits(8, "gamestate_op")
            if gamestate_op == 8:  # svc_EOF
                stop = True
            elif gamestate_op == 3:  # svc_configstring
                i = buffer.read_bits(16, "configstring_index")
                config_string = buffer.read_string("configstring")
            elif gamestate_op == 4:  # svc_baseline
                entity_number = buffer.read_bits(defs.GENTITYNUM_BITS, "entity_number")
                if buffer.read_bit("update_or_delete") == 0:
                    self.baselines[entity_number] = self.read_delta_entity(buffer, {}, trace)
            else:
                raise Exception("unknown command in gamestate: {}".format(gamestate_op))
            trace.end()
        buffer.read_bits(32, "client_number")
        self.checksum_feed = buffer.read_bits(32, "checksum_feed")

    def parse_download(self, buffer, trace):
        block = buffer.read_bits(16, "block")
        if block == 0:
            buffer.read_bits(32, "download_size")
        size = buffer.read_bits(16, "size")
        if size > 0:
            trace.add("data", "[...]")
            for _ in range(size):
                buffer.read_bits(8)

    def read_delta_entity(self, buffer, old, trace):
        entity = old.copy()
        if buffer.read_bit("entity_changed") == 1:
            field_count = buffer.read_bits(8, "field_count")
            for i in range(field_count):
                trace.begin("_field")
                if buffer.read_bit("field_changed") == 1:
                    field = defs.ENTITY_FIELDS[self.protocol][i]
                    if field.bits == 0:  # float
                        if buffer.read_bit("float_is_not_zero") == 1:
                            if buffer.read_bit("int_or_float") == 0:
                                entity[field.name] = buffer.read_int_float(field.name)
                            else:
                                entity[field.name] = buffer.read_float(field.name)
                        else:
                            entity[field.name] = 0
                    else:
                        if buffer.read_bit("int_is_not_zero") == 1:
                            entity[field.name] = buffer.read_bits(field.bits, field.name)
                        else:
                            entity[field.name] = 0
                trace.end()

        return entity


class UserCommand:

    def __init__(self):
        self.angles = [0, 0, 0]
        self.forwardmove = 0
        self.rightmove = 0
        self.upmove = 0
        self.buttons = 0
        self.weapon = 0
        # Quake Live has two more:
        self.unknown1 = 0
        self.unknown2 = 0


class Q3Proxy:

    def __init__(self, config):
        self.config = config
        self.clients_by_address_pair = {}
        self.clients_by_server_socket = {}
        self.sockets = []

    def get_client(self, client_address, server_address):
        client = self.clients_by_address_pair.get((client_address, server_address))
        if client is None:
            if self.config.debug_level >= 1:
                print("New client connection from {} to {}.".format(client_address, server_address))
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sockets.append(server_socket)
            client = Client(client_address, server_socket, self.config)
            self.clients_by_address_pair[(client_address, server_address)] = client
            self.clients_by_server_socket[server_socket] = client
        client.last_active = time.time()
        self.remove_inactive_clients()
        return client

    def remove_inactive_clients(self):
        now = time.time()
        for address_pair, client in list(self.clients_by_address_pair.items()):
            if now - client.last_active > 60:
                if self.config.debug_level >= 2:
                    print("Cleaning up inactive client: {}".format(address_pair))
                del self.clients_by_address_pair[address_pair]
                del self.clients_by_server_socket[client.server_socket]
                self.sockets.remove(client.server_socket)
                try:
                    client.server_socket.close()
                except:
                    if self.config.print_exceptions:
                        print(traceback.format_exc())

    def run(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.bind(('', self.config.listen_port))
        self.sockets.append(client_socket)

        socks = self.config.socks_port is not None

        if not socks and self.config.debug_level >= 1:
            print("Listening on port {}...".format(self.config.listen_port))

        if socks:
            socks_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socks_socket.setblocking(0)
            socks_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            socks_socket.bind(('', self.config.socks_port))
            socks_socket.listen()
            self.sockets.append(socks_socket)
            socks_public_address = address_to_bytes(
                (self.config.socks_public_address, self.config.listen_port))
            socks_states = {}
            if self.config.debug_level >= 1:
                print("Listening on SOCKS port {}...".format(self.config.socks_port))

        queue = []

        while True:
            now = time.time()
            while queue and queue[0].time <= now:
                task = queue.pop(0)
                task.task()

            if queue:
                timeout = queue[0].time - now
            else:
                timeout = None

            ready_to_read, _, _ = select.select(self.sockets, [], [], timeout)
            for ready_socket in ready_to_read:
                if ready_socket == client_socket:
                    try:
                        data, client_address = client_socket.recvfrom(4096)
                    except ConnectionResetError:
                        # This means a previous call to sendto on this socket failed.
                        # We don't know which client it was so we just do nothing.
                        if self.config.debug_level >= 2:
                            print("Lost connection to client.")
                        continue
                    if self.config.debug_level >= 2:
                        print("Received packet from {} on client socket.".format(client_address))

                    if socks:
                        server_address = socket.inet_ntoa(data[4:8])
                        (server_port,) = struct.unpack('!H', data[8:10])
                        if self.config.debug_level >= 2:
                            print("Packet is for server at {}.".format(
                                (server_address, server_port)))
                        data = data[10:]
                    else:
                        server_address = self.config.server_address
                        server_port = self.config.server_port

                    client = self.get_client(client_address, (server_address, server_port))

                    try:
                        trace = Trace()
                        processed_data = client.process_client_packet(data, trace)
                        if self.config.print_packets_as_html:
                            print(trace.get_as_html())
                    except:
                        if self.config.print_exceptions:
                            print(traceback.format_exc())
                        processed_data = data
                    queue.append(
                        create_send_task(client.server_socket, processed_data,
                                         time.time() + self.config.client_to_server_delay / 1000,
                                         self.config.client_to_server_packet_loss / 100,
                                         (server_address, server_port)))
                elif socks and ready_socket == socks_socket:
                    client_socks_socket, client_address = socks_socket.accept()
                    if self.config.debug_level >= 1:
                        print("New SOCKS connection from {}.".format(client_address))
                    self.sockets.append(client_socks_socket)
                    socks_states[client_socks_socket] = 1
                elif socks and ready_socket in socks_states:
                    try:
                        data = ready_socket.recv(4096)
                    except ConnectionResetError:
                        if self.config.debug_level >= 1:
                            print("SOCKS connection closed.")
                        self.sockets.remove(ready_socket)
                        continue
                    if self.config.debug_level >= 2:
                        print(
                            "Received on SOCKS port (state={}):".format(socks_states[ready_socket]),
                            data)
                    if data == b'':
                        if self.config.debug_level >= 1:
                            print("SOCKS connection closed.")
                        self.sockets.remove(ready_socket)
                    elif socks_states[ready_socket] == 1:
                        ready_socket.send(b'\x05\x00')
                        socks_states[ready_socket] = 2
                    elif socks_states[ready_socket] == 2:
                        ready_socket.send(b'\x05\x00\x00\x01' + socks_public_address)
                        socks_states[ready_socket] = 3
                else:
                    client = self.clients_by_server_socket[ready_socket]
                    data, server_address = ready_socket.recvfrom(4096)
                    if self.config.debug_level >= 2:
                        print("Received packet from {} on server socket.".format(server_address))
                    try:
                        trace = Trace()
                        client.process_server_packet(data, trace)
                        if self.config.print_packets_as_html:
                            print(trace.get_as_html())
                    except:
                        if self.config.print_exceptions:
                            print(traceback.format_exc())
                    if socks:
                        data = b'\x00\x00\x00\x01' + address_to_bytes(server_address) + data
                    queue.append(
                        create_send_task(client_socket, data,
                                         time.time() + self.config.server_to_client_delay / 1000,
                                         self.config.server_to_client_packet_loss / 100,
                                         client.client_address))

    def process_dump_file(self, dump_filename):
        from scapy.all import rdpcap, IP, UDP
        client = Client(None, None, self.config)
        packets = rdpcap(dump_filename)
        for packet in packets:
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                continue
            try:
                trace = Trace()
                if ((self.config.server_address,
                     self.config.server_port) == (packet.getlayer(IP).src,
                                                  packet.getlayer(UDP).sport)):
                    client.process_server_packet(bytes(packet.getlayer(UDP).payload), trace)
                if ((self.config.server_address,
                     self.config.server_port) == (packet.getlayer(IP).dst,
                                                  packet.getlayer(UDP).dport)):
                    client.process_client_packet(bytes(packet.getlayer(UDP).payload), trace)
                if self.config.print_packets_as_html:
                    print(trace.get_as_html())
            except:
                if self.config.print_exceptions:
                    print(traceback.format_exc())


def main():
    config = parse_arguments()
    if not validate_arguments(config):
        sys.exit(1)

    q3proxy = Q3Proxy(config)

    if config.print_packets_as_html:
        print(defs.HTML_HEADER)

    if config.read_dump:
        q3proxy.process_dump_file(config.read_dump)
    else:
        q3proxy.run()


if __name__ == '__main__':
    main()
