"""
	A pure python ping implementation using raw sockets.

	Note that ICMP messages can only be send from processes running as root

"""

import os
import select
import signal
import struct
import sys
import time
import socket, sys
from math import ceil
from random import choice

from impacket import ImpactPacket
import ipaddr

import socket
import fcntl
import struct

if sys.platform.startswith("win32"):
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

# ICMP parameters
ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

MAX_SLEEP = 1000
HOST_NUMBER = 5


def is_valid_ip4_address(addr):
    parts = addr.split(".")
    if not len(parts) == 4:
        return False
    for part in parts:
        try:
            number = int(part)
        except ValueError:
            return False
        if number > 255 or number < 0:
            return False
    return True


def to_ip(addr):
    if is_valid_ip4_address(addr):
        return addr
    return socket.gethostbyname(addr)


class Response(object):
    def __init__(self):
        self.max_rtt = None
        self.min_rtt = None
        self.avg_rtt = None
        self.packet_lost = None
        self.ret_code = None
        self.output = []

        self.packet_size = None
        self.timeout = None
        self.source = None
        self.destination = None
        self.destination_ip = None


class Ping(object):
    def __init__(self, me, source, destination, timeout=1000, packet_size=200, own_id=None, quiet_output=False,
                 udp=False,
                 bind=None):
        self.quiet_output = quiet_output
        if quiet_output:
            self.response = Response()
            self.response.destination = destination
            self.response.timeout = timeout
            self.response.packet_size = packet_size

        self.me = me
        self.destination = destination
        self.source = source
        self.timeout = timeout
        self.packet_size = packet_size
        self.udp = udp
        self.bind = bind
        self.packet_number = {}
        self.return_home_file_name = None
        self.return_home_ip = None
        self.received_files = {}

        try:
            self.current_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.current_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Bind the socket to a source address
            if self.bind:
                print('self.bind: ', self.bind)
                self.current_socket.bind((self.bind, 0))  # Port number is irrelevant for ICMP

        except socket.error, (errno, msg):
            if errno == 1:
                # Operation not permitted - Add more information to traceback
                # the code should run as administrator
                etype, evalue, etb = sys.exc_info()
                evalue = etype(
                    "%s - Note that ICMP messages can only be sent from processes running as root." % evalue
                )
                raise etype, evalue, etb
            raise  # raise the original error

        if own_id is None:
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        try:
            self.dest_ip = to_ip(self.destination)
            if quiet_output:
                self.response.destination_ip = self.dest_ip
        except socket.gaierror as e:
            self.print_unknown_host(e)
        else:
            self.print_start()

        self.seq_number = 0
        self.send_count = 0
        self.receive_count = 0
        self.min_time = 999999999
        self.max_time = 0.0
        self.total_time = 0.0

    def __deinit__(self):
        self.current_socket.close()

    # --------------------------------------------------------------------------

    def print_start(self):
        msg = "\nPYTHON-PING %s (%s): %d data bytes" % (self.destination, self.dest_ip, self.packet_size)
        if self.quiet_output:
            self.response.output.append(msg)
        else:
            print(msg)

    def print_unknown_host(self, e):
        msg = "\nPYTHON-PING: Unknown host: %s (%s)\n" % (self.destination, e.args[1])
        if self.quiet_output:
            self.response.output.append(msg)
            self.response.ret_code = 1
        else:
            print(msg)

        raise Exception, "unknown_host"

    # sys.exit(-1)

    def print_exit(self):
        msg = "\n----%s PYTHON PING Statistics----" % (self.destination)

        if self.quiet_output:
            self.response.output.append(msg)
        else:
            print(msg)

        lost_count = self.send_count - self.receive_count
        # print("%i packets lost" % lost_count)
        lost_rate = float(lost_count) / self.send_count * 100.0

        msg = "%d packets transmitted, %d packets received, %0.1f%% packet loss" % (
            self.send_count, self.receive_count, lost_rate)

        if self.quiet_output:
            self.response.output.append(msg)
            self.response.packet_lost = lost_count
        else:
            print(msg)

        if self.receive_count > 0:
            msg = "round-trip (ms)  min/avg/max = %0.3f/%0.3f/%0.3f" % (
                self.min_time, self.total_time / self.receive_count, self.max_time)
            if self.quiet_output:
                self.response.min_rtt = '%.3f' % self.min_time
                self.response.avg_rtt = '%.3f' % (self.total_time / self.receive_count)
                self.response.max_rtt = '%.3f' % self.max_time
                self.response.output.append(msg)
            else:
                print(msg)

        if self.quiet_output:
            self.response.output.append('\n')
        else:
            print('')

    # --------------------------------------------------------------------------

    def signal_handler(self, signum, frame):
        """
        Handle print_exit via signals
        """
        self.print_exit()
        msg = "\n(Terminated with signal %d)\n" % (signum)

        if self.quiet_output:
            self.response.output.append(msg)
            self.response.ret_code = 0
        else:
            print(msg)

        sys.exit(0)

    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler)  # Handle Ctrl-C
        if hasattr(signal, "SIGBREAK"):
            # Handle Ctrl-Break e.g. under Windows
            signal.signal(signal.SIGBREAK, self.signal_handler)

    # --------------------------------------------------------------------------

    def header2dict(self, names, struct_format, data):
        """ unpack the raw received IP and ICMP header informations to a dict """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    # --------------------------------------------------------------------------

    # send an ICMP ECHO_REQUEST packet
    def send_one_ping(self, src, dst, data, id):

        # Create a new IP packet and set its source and destination IP addresses
        ip = ImpactPacket.IP()
        ip.set_ip_src(src)
        ip.set_ip_dst(dst)

        # Create a new ICMP ECHO_REQUEST packet
        icmp = ImpactPacket.ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)

        # inlude a small payload inside the ICMP packet
        # and have the ip packet contain the ICMP packet
        icmp.contains(ImpactPacket.Data(data))
        ip.contains(icmp)

        # give the ICMP packet some ID
        icmp.set_icmp_id(id)

        # set the ICMP packet checksum
        icmp.set_icmp_cksum(0)
        icmp.auto_checksum = 1

        send_time = default_timer()

        # send the provided ICMP packet over a 3rd socket
        try:
            self.current_socket.sendto(ip.get_packet(), (dst, 1))  # Port number is irrelevant for ICMP
        except socket.error as e:
            self.response.output.append("General failure (%s)" % (e.args[1]))
            self.current_socket.close()
            return

        return send_time

    # Receive the ping from the socket.
    # timeout = in ms
    def receiver(self):
        while True:
            # print("return_home_file_name: %s" % self.return_home_file_name)
            if self.return_home_file_name is not None and self.return_home_ip is None and len(self.received_files) == self.packet_number[self.return_home_file_name]:
                f = open(self.return_home_file_name, "w+")
                for key, value in sorted(self.received_files.iteritems()):
                    f.write(value)
                f.close()
                print("%s saved successfully!" % self.return_home_file_name)
                self.received_files = {}
                self.return_home_file_name = None
            inputready, outputready, exceptready = select.select([self.current_socket, sys.stdin], [], [])
            for sock in inputready:
                # incoming message from remote server
                if sock == self.current_socket:
                    # print("ping socket")
                    self.receive_one_ping()

                # user entered a message
                else:
                    msg = sys.stdin.readline()
                    msg = msg.lower()
                    splittedMsg = msg.split(" ")
                    cmd = splittedMsg[0]
                    if cmd == "return_home":
                        host_list = (range(1, HOST_NUMBER + 1))
                        host_list.remove(self.me)
                        source_num = choice(host_list)
                        source = "10.0.0." + str(source_num)
                        host_list.remove(source_num)
                        dest_num = choice(host_list)
                        dest = "10.0.0." + str(dest_num)
                        # print("source: %s" % source)
                        # print("dest: %s" % dest)
                        self.return_home_file_name = splittedMsg[1].replace("\n", "")
                        self.send_one_ping(source, dest,
                                           "return_home;" + self.return_home_file_name + ";" + self.source, 0x03)
                    elif cmd == "send":
                        dest = splittedMsg[2].replace("\n", "")
                        dest_num = int(dest.split(".")[-1])
                        host_list = (range(1, HOST_NUMBER + 1))
                        host_list.remove(dest_num)
                        host_list.remove(self.me)

                        fileName = splittedMsg[1]
                        fileSize = os.stat(fileName).st_size
                        chunkSize = self.packet_size - len(fileName) - 1
                        num_of_packets = ceil(float(fileSize) / chunkSize)
                        self.packet_number[fileName] = num_of_packets
                        print(self.packet_number)
                        # print(num_of_packets)

                        file = open(fileName)
                        id = 1
                        chunk = file.read(chunkSize)
                        while chunk != "":
                            chunk = fileName + ";" + chunk
                            source = "10.0.0." + str(choice(host_list))
                            self.send_one_ping(source, dest, chunk, id)
                            id += 1
                            chunk = file.read(chunkSize)
                            # print("source: %s" % source)
                            # print("dest: %s" % dest)
                        # print("---- file sent")
                        file.close()
                        try:
                            os.remove(fileName)
                        except OSError:
                            pass
                    elif cmd == "test":
                        print("recieved files: %s" % self.received_files)

    def receive_one_ping(self):

        packet_data, address = self.current_socket.recvfrom(ICMP_MAX_RECV)

        icmp_header = self.header2dict(
            names=[
                "type", "code", "checksum",
                "packet_id", "seq_number"
            ],
            struct_format="!BBHHH",
            data=packet_data[20:28]
        )
        # print("type %s" % icmp_header["type"])

        receive_time = default_timer()

        ip_header = self.header2dict(
            names=[
                "version", "type", "length",
                "id", "flags", "ttl", "protocol",
                "checksum", "src_ip", "dest_ip"
            ],
            struct_format="!BBHHHBBHII",
            data=packet_data[:20]
        )

        data = packet_data[28:]
        # print("data: %s" % data)
        splitted_data = data.split(";")

        # print(splitted_data)

        # print("----")
        # print(self.return_home_file_name)
        # print(splitted_data[0])
        # print("--- %s - %s" % (self.return_home_file_name is not None, self.return_home_file_name == splitted_data[0]))
        if self.return_home_file_name is not None and self.return_home_file_name == splitted_data[0]:
            # print("here")
            if self.return_home_ip is None:
                self.received_files[icmp_header["packet_id"]] = splitted_data[1]
            else:
                self.send_one_ping(self.source, self.return_home_ip, data, icmp_header["packet_id"])
                self.return_home_file_name = None
                self.return_home_ip = None

        elif int(icmp_header["type"]) == ICMP_ECHOREPLY:
            # print("reply")
            host_list = (range(1, HOST_NUMBER + 1))
            host_list.remove(self.me)
            source_num = choice(host_list)
            source = "10.0.0." + str(source_num)
            host_list.remove(source_num)
            dest_num = choice(host_list)
            dest = "10.0.0." + str(dest_num)
            # print("source: %s" % source)
            # print("dest: %s" % dest)
            self.send_one_ping(source, dest, data, icmp_header["packet_id"])

        if splitted_data[0] == "return_home" and self.return_home_file_name is None:
            # print("here222")
            self.return_home_file_name = splitted_data[1].replace("\n", "")
            self.return_home_ip = splitted_data[2]

        # if int(icmp_header["type"]) == ICMP_ECHO:
        #     print("request")
        packet_size = len(packet_data) - 28
        ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
        # XXX: Why not ip = address[0] ???
        return receive_time, packet_size, ip, ip_header, icmp_header


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


if __name__ == "__main__":
    cur_hostname = sys.argv[1]
    cur_ipaddress = get_ip_address(str(cur_hostname) + '-eth0')
    print("my ip address: %s" % cur_ipaddress)
    p = Ping(int(cur_hostname[1:]), cur_ipaddress, "")
    p.receiver()
