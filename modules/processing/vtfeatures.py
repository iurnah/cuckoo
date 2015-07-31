# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime
import re
import socket
import struct
import tempfile
import urlparse

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import NetlogParser, BsonParser
from lib.cuckoo.common.utils import convert_to_printable, logtime
from lib.cuckoo.common.utils import cleanup_value
from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError
from modules.processing.network import NetworkAnalysis 

log = logging.getLogger(__name__)

# processing pcap files.
try:
    import dpkt
    IS_DPKT = True
except ImportError:
    IS_DPKT = False

# Imports for the batch sort.
# http://stackoverflow.com/questions/10665925/how-to-sort-huge-files-with-python
# http://code.activestate.com/recipes/576755/
import heapq
from itertools import islice
from collections import namedtuple

Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])

class Pcap:
    """Reads network data from PCAP file."""

    def __init__(self, filepath):
        """Creates a new instance.
        @param filepath: path to PCAP file
        """
        self.filepath = filepath

        # List of all hosts.
        self.hosts = []
        # List containing all non-private IP addresses.
        self.unique_hosts = []
        # List of unique domains.
        self.unique_domains = []
        # List containing all TCP packets.
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        # List containing all UDP packets.
        self.udp_connections = []
        self.udp_connections_seen = set()
        # List containing all ICMP requests.
        self.icmp_requests = []
        # List containing all HTTP requests.
        self.http_requests = {}
        # List containing all DNS requests.
        self.dns_requests = {}
        self.dns_answers = set()
        # List containing all SMTP requests.
        self.smtp_requests = []
        # Reconstruncted SMTP flow.
        self.smtp_flow = {}
        # List containing all IRC requests.
        self.irc_requests = []
        # Dictionary containing all the results of this processing.
        self.results = {}

    def _dns_gethostbyname(self, name):
        """Get host by name wrapper.
        @param name: hostname.
        @return: IP address or blank
        """
        if Config().processing.resolve_dns:
            ip = resolve(name)
        else:
            ip = ""
        return ip

    def _is_private_ip(self, ip):
        """Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
                 a private network block.
        """
        networks = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "240.0.0.0/4",
            "255.255.255.255/32",
            "224.0.0.0/4"
        ]

        for network in networks:
            try:
                ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]

                netaddr, bits = network.split("/")

                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - int(bits))) - 1

                if ipaddr <= network_high and ipaddr >= network_low:
                    return True
            except:
                continue

        return False

    def _add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        try:
            if connection["src"] not in self.hosts:
                ip = convert_to_printable(connection["src"])

                # We consider the IP only if it hasn't been seen before.
                if ip not in self.hosts:
                    # If the IP is not a local one, this might be a leftover
                    # packet as described in issue #249.
                    if self._is_private_ip(ip):
                        self.hosts.append(ip)

            if connection["dst"] not in self.hosts:
                ip = convert_to_printable(connection["dst"])

                if ip not in self.hosts:
                    self.hosts.append(ip)

                    # We add external IPs to the list, only the first time
                    # we see them and if they're the destination of the
                    # first packet they appear in.
                    if not self._is_private_ip(ip):
                        self.unique_hosts.append(ip)
        except:
            pass

    def _tcp_dissect(self, conn, data):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        if self._check_http(data):
            self._add_http(data, conn["dport"])
        # SMTP.
        if conn["dport"] == 25:
            self._reassemble_smtp(conn, data)
        # IRC.
        if conn["dport"] != 21 and self._check_irc(data):
            self._add_irc(data)

    def _udp_dissect(self, conn, data):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # Select DNS and MDNS traffic.
        if conn["dport"] == 53 or conn["sport"] == 53 or conn["dport"] == 5353 or conn["sport"] == 5353:
            if self._check_dns(data):
                self._add_dns(data)

    def _check_icmp(self, icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP) and \
                len(icmp_data.data) > 0
        except:
            return False

    def _icmp_dissect(self, conn, data):
        """Runs all ICMP dissectors.
        @param conn: connection.
        @param data: payload data.
        """

        if self._check_icmp(data):
            # If ICMP packets are coming from the host, it probably isn't
            # relevant traffic, hence we can skip from reporting it.
            if conn["src"] == Config().resultserver.ip:
                return

            entry = {}
            entry["src"] = conn["src"]
            entry["dst"] = conn["dst"]
            entry["type"] = data.type

            # Extract data from dpkg.icmp.ICMP.
            try:
                entry["data"] = convert_to_printable(data.data.data)
            except:
                entry["data"] = ""

            self.icmp_requests.append(entry)

    def _check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except:
            return False

        return True

    def _add_dns(self, udpdata):
        """Adds a DNS data flow.
        @param udpdata: UDP data flow.
        """
        dns = dpkt.dns.DNS(udpdata)

        # DNS query parsing.
        query = {}

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
                dns.qr == dpkt.dns.DNS_R or \
                dns.opcode == dpkt.dns.DNS_QUERY or True:
            # DNS question.
            try:
                q_name = dns.qd[0].name
                q_type = dns.qd[0].type
            except IndexError:
                return False

            query["request"] = q_name
            if q_type == dpkt.dns.DNS_A:
                query["type"] = "A"
            if q_type == dpkt.dns.DNS_AAAA:
                query["type"] = "AAAA"
            elif q_type == dpkt.dns.DNS_CNAME:
                query["type"] = "CNAME"
            elif q_type == dpkt.dns.DNS_MX:
                query["type"] = "MX"
            elif q_type == dpkt.dns.DNS_PTR:
                query["type"] = "PTR"
            elif q_type == dpkt.dns.DNS_NS:
                query["type"] = "NS"
            elif q_type == dpkt.dns.DNS_SOA:
                query["type"] = "SOA"
            elif q_type == dpkt.dns.DNS_HINFO:
                query["type"] = "HINFO"
            elif q_type == dpkt.dns.DNS_TXT:
                query["type"] = "TXT"
            elif q_type == dpkt.dns.DNS_SRV:
                query["type"] = "SRV"

            # DNS answer.
            query["answers"] = []
            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A:
                    ans["type"] = "A"
                    try:
                        ans["data"] = socket.inet_ntoa(answer.rdata)
                    except socket.error:
                        continue
                elif answer.type == dpkt.dns.DNS_AAAA:
                    ans["type"] = "AAAA"
                    try:
                        ans["data"] = socket.inet_ntop(socket.AF_INET6,
                                                       answer.rdata)
                    except (socket.error, ValueError):
                        continue
                elif answer.type == dpkt.dns.DNS_CNAME:
                    ans["type"] = "CNAME"
                    ans["data"] = answer.cname
                elif answer.type == dpkt.dns.DNS_MX:
                    ans["type"] = "MX"
                    ans["data"] = answer.mxname
                elif answer.type == dpkt.dns.DNS_PTR:
                    ans["type"] = "PTR"
                    ans["data"] = answer.ptrname
                elif answer.type == dpkt.dns.DNS_NS:
                    ans["type"] = "NS"
                    ans["data"] = answer.nsname
                elif answer.type == dpkt.dns.DNS_SOA:
                    ans["type"] = "SOA"
                    ans["data"] = ",".join([answer.mname,
                                           answer.rname,
                                           str(answer.serial),
                                           str(answer.refresh),
                                           str(answer.retry),
                                           str(answer.expire),
                                           str(answer.minimum)])
                elif answer.type == dpkt.dns.DNS_HINFO:
                    ans["type"] = "HINFO"
                    ans["data"] = " ".join(answer.text)
                elif answer.type == dpkt.dns.DNS_TXT:
                    ans["type"] = "TXT"
                    ans["data"] = " ".join(answer.text)

                # TODO: add srv handling
                query["answers"].append(ans)

            self._add_domain(query["request"])

            reqtuple = query["type"], query["request"]
            if reqtuple not in self.dns_requests:
                self.dns_requests[reqtuple] = query
            else:
                new_answers = set((i["type"], i["data"]) for i in query["answers"]) - self.dns_answers
                self.dns_requests[reqtuple]["answers"] += [dict(type=i[0], data=i[1]) for i in new_answers]

        return True

    def _add_domain(self, domain):
        """Add a domain to unique list.
        @param domain: domain name.
        """
        filters = [
            ".*\\.windows\\.com$",
            ".*\\.in\\-addr\\.arpa$"
        ]

        regexps = [re.compile(filter) for filter in filters]
        for regexp in regexps:
            if regexp.match(domain):
                return

        for entry in self.unique_domains:
            if entry["domain"] == domain:
                return

        self.unique_domains.append({"domain": domain,
                                    "ip": self._dns_gethostbyname(domain)})

    def _check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if r.method is not None or r.version is not None or \
                    r.uri is not None:
                return True
            return False

        return True

    def _add_http(self, tcpdata, dport):
        """Adds an HTTP flow.
        @param tcpdata: TCP data flow.
        @param dport: destination port.
        """
        if tcpdata in self.http_requests:
            self.http_requests[tcpdata]["count"] += 1
            return True

        try:
            http = dpkt.http.Request()
            http.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            entry = {"count": 1}

            if "host" in http.headers:
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = ""

            entry["port"] = dport

            # Manually deal with cases when destination port is not the
            # default one and it is not included in host header.
            netloc = entry["host"]
            if dport != 80 and ":" not in netloc:
                netloc += ":" + str(entry["port"])

            entry["data"] = convert_to_printable(tcpdata)
            url = urlparse.urlunparse(("http", netloc, http.uri,
                                       None, None, None))
            entry["uri"] = convert_to_printable(url)
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(http.uri)

            if "user-agent" in http.headers:
                entry["user-agent"] = \
                    convert_to_printable(http.headers["user-agent"])

            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)

            self.http_requests[tcpdata] = entry
        except Exception:
            return False

        return True

    def _reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        if conn["dst"] in self.smtp_flow:
            self.smtp_flow[conn["dst"]] += data
        else:
            self.smtp_flow[conn["dst"]] = data

    def _process_smtp(self):
        """Process SMTP flow."""
        for conn, data in self.smtp_flow.iteritems():
            # Detect new SMTP flow.
            if data.startswith(("EHLO", "HELO")):
                self.smtp_requests.append({"dst": conn, "raw": data})

    def _check_irc(self, tcpdata):
        """
        Checks for IRC traffic.
        @param tcpdata: tcp data flow
        """
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcpdata)

    def _add_irc(self, tcpdata):
        """
        Adds an IRC communication.
        @param tcpdata: TCP data in flow
        @param dport: destination port
        """

        try:
            reqc = ircMessage()
            reqs = ircMessage()
            filters_sc = ["266"]
            self.irc_requests = self.irc_requests + \
                reqc.getClientMessages(tcpdata) + \
                reqs.getServerMessagesFilter(tcpdata, filters_sc)
        except Exception:
            return False

        return True

    def run(self):
        """Process PCAP.
        @return: dict with network analysis data.
        """

        try:
            file = open(self.filepath, "rb")
        except (IOError, OSError):
            log.error("Unable to open %s" % self.filepath)
            return self.results

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            log.error("Unable to read PCAP file at path \"%s\".",
                      self.filepath)
            return self.results
        except ValueError:
            log.error("Unable to read PCAP file at path \"%s\". File is "
                      "corrupted or wrong format." % self.filepath)
            return self.results

        offset = file.tell()
        first_ts = None
        for ts, buf in pcap:
            if not first_ts:
                first_ts = ts

            try:
                ip = iplayer_from_raw(buf, pcap.datalink())

                connection = {}
                if isinstance(ip, dpkt.ip.IP):
                    connection["src"] = socket.inet_ntoa(ip.src)
                    connection["dst"] = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    connection["src"] = socket.inet_ntop(socket.AF_INET6,
                                                         ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6,
                                                         ip.dst)
                else:
                    offset = file.tell()
                    continue

                self._add_hosts(connection)

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP):
                        tcp = dpkt.tcp.TCP(tcp)

                    if len(tcp.data) > 0:
                        connection["sport"] = tcp.sport
                        connection["dport"] = tcp.dport
                        self._tcp_dissect(connection, tcp.data)

                        src, sport, dst, dport = (connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.tcp_connections_seen or (src, sport, dst, dport) in self.tcp_connections_seen):
                            self.tcp_connections.append((src, sport, dst, dport, offset, ts-first_ts))
                            self.tcp_connections_seen.add((src, sport, dst, dport))

                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if not isinstance(udp, dpkt.udp.UDP):
                        udp = dpkt.udp.UDP(udp)

                    if len(udp.data) > 0:
                        connection["sport"] = udp.sport
                        connection["dport"] = udp.dport
                        self._udp_dissect(connection, udp.data)

                        src, sport, dst, dport = (connection["src"], connection["sport"], connection["dst"], connection["dport"])
                        if not ((dst, dport, src, sport) in self.udp_connections_seen or (src, sport, dst, dport) in self.udp_connections_seen):
                            self.udp_connections.append((src, sport, dst, dport, offset, ts-first_ts))
                            self.udp_connections_seen.add((src, sport, dst, dport))

                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data
                    if not isinstance(icmp, dpkt.icmp.ICMP):
                        icmp = dpkt.icmp.ICMP(icmp)

                    self._icmp_dissect(connection, icmp)

                offset = file.tell()
            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        file.close()

        # Post processors for reconstructed flows.
        self._process_smtp()

        # Build results dict.
        self.results["hosts"] = self.unique_hosts
        self.results["domains"] = self.unique_domains
        self.results["tcp"] = [conn_from_flowtuple(i) for i in self.tcp_connections]
        self.results["udp"] = [conn_from_flowtuple(i) for i in self.udp_connections]
        self.results["icmp"] = self.icmp_requests
        self.results["http"] = self.http_requests.values()
        self.results["dns"] = self.dns_requests.values()
        self.results["smtp"] = self.smtp_requests
        self.results["irc"] = self.irc_requests

        return self.results

def iplayer_from_raw(raw, linktype=1):
    """Converts a raw packet to a dpkt packet regarding of link type.
    @param raw: raw packet
    @param linktype: integer describing link type as expected by dpkt
    """
    if linktype == 1:  # ethernet
        pkt = dpkt.ethernet.Ethernet(raw)
        ip = pkt.data
    elif linktype == 101:  # raw
        ip = dpkt.ip.IP(raw)
    else:
        raise CuckooProcessingError("unknown PCAP linktype")
    return ip

def conn_from_flowtuple(ft):
    """Convert the flow tuple into a dictionary (suitable for JSON)"""
    sip, sport, dip, dport, offset, relts = ft
    return {"src": sip, "sport": sport,
            "dst": dip, "dport": dport,
            "offset": offset, "time": relts}

# input_iterator should be a class that also supports writing so we can use
# it for the temp files
# this code is mostly taken from some SO post, can't remember the url though
def batch_sort(input_iterator, output_path, buffer_size=32000, output_class=None):
    """batch sort helper with temporary files, supports sorting large stuff"""
    if not output_class:
        output_class = input_iterator.__class__

    chunks = []
    try:
        while True:
            current_chunk = list(islice(input_iterator, buffer_size))
            if not current_chunk:
                break
            current_chunk.sort()
            fd, filepath = tempfile.mkstemp()
            os.close(fd)
            output_chunk = output_class(filepath)
            chunks.append(output_chunk)

            for elem in current_chunk:
                output_chunk.write(elem.obj)
            output_chunk.close()

        output_file = output_class(output_path)
        for elem in heapq.merge(*chunks):
            output_file.write(elem.obj)
        output_file.close()
    finally:
        for chunk in chunks:
            try:
                chunk.close()
                os.remove(chunk.name)
            except Exception:
                pass

# magic
class SortCap(object):
    """SortCap is a wrapper around the packet lib (dpkt) that allows us to sort pcaps
    together with the batch_sort function above."""

    def __init__(self, path, linktype=1):
        self.name = path
        self.linktype = linktype
        self.fd = None
        self.ctr = 0  # counter to pass through packets without flow info (non-IP)
        self.conns = set()

    def write(self, p):
        if not self.fd:
            self.fd = dpkt.pcap.Writer(open(self.name, "wb"), linktype=self.linktype)
        self.fd.writepkt(p.raw, p.ts)

    def __iter__(self):
        if not self.fd:
            self.fd = dpkt.pcap.Reader(open(self.name, "rb"))
            self.fditer = iter(self.fd)
            self.linktype = self.fd.datalink()
        return self

    def close(self):
        self.fd.close()
        self.fd = None

    def next(self):
        rp = next(self.fditer)
        if rp is None:
            return None
        self.ctr += 1

        ts, raw = rp
        rpkt = Packet(raw, ts)

        sip, dip, sport, dport, proto = flowtuple_from_raw(raw, self.linktype)

        # check other direction of same flow
        if (dip, sip, dport, sport, proto) in self.conns:
            flowtuple = (dip, sip, dport, sport, proto)
        else:
            flowtuple = (sip, dip, sport, dport, proto)

        self.conns.add(flowtuple)
        return Keyed((flowtuple, ts, self.ctr), rpkt)

def sort_pcap(inpath, outpath):
    """Use SortCap class together with batch_sort to sort a pcap"""
    inc = SortCap(inpath)
    batch_sort(inc, outpath, output_class=lambda path: SortCap(path, linktype=inc.linktype))
    return 0

def flowtuple_from_raw(raw, linktype=1):
    """Parse a packet from a pcap just enough to gain a flow description tuple"""
    ip = iplayer_from_raw(raw, linktype)

    if isinstance(ip, dpkt.ip.IP):
        sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        proto = ip.p

        if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
            l3 = ip.data
            sport, dport = l3.sport, l3.dport
        else:
            sport, dport = 0, 0

    else:
        sip, dip, proto = 0, 0, -1
        sport, dport = 0, 0

    flowtuple = (sip, dip, sport, dport, proto)
    return flowtuple

def payload_from_raw(raw, linktype=1):
    """Get the payload from a packet, the data below TCP/UDP basically"""
    ip = iplayer_from_raw(raw, linktype)
    try:
        return ip.data.data
    except:
        return ""

def next_connection_packets(piter, linktype=1):
    """Extract all packets belonging to the same flow from a pcap packet iterator"""
    first_ft = None

    for ts, raw in piter:
        ft = flowtuple_from_raw(raw, linktype)
        if not first_ft:
            first_ft = ft

        sip, dip, sport, dport, proto = ft
        if not (first_ft == ft or first_ft == (dip, sip, dport, sport, proto)):
            break

        yield {
            "src": sip, "dst": dip, "sport": sport, "dport": dport,
            "raw": payload_from_raw(raw, linktype).encode("base64"),
            "direction": first_ft == ft,
        }

def packets_for_stream(fobj, offset):
    """Open a PCAP, seek to a packet offset, then get all packets belonging to the same connection"""
    pcap = dpkt.pcap.Reader(fobj)
    pcapiter = iter(pcap)
    ts, raw = pcapiter.next()

    fobj.seek(offset)
    for p in next_connection_packets(pcapiter, linktype=pcap.datalink()):
        yield p

# parsing the log file (bson)
class ParseProcessLog(list):
    """Parses process log file."""

    def __init__(self, log_path):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.fd = None
        self.parser = None

        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.first_seen = None
        self.calls = self
        self.lastcall = None
        self.call_id = 0

        if os.path.exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

    def parse_first_and_reset(self):
        self.fd = open(self._log_path, "rb")

        if self._log_path.endswith(".bson"):
            self.parser = BsonParser(self)
        elif self._log_path.endswith(".raw"):
            self.parser = NetlogParser(self)
        else:
            self.fd.close()
            self.fd = None
            return

        # Get the process information from file to determine
        # process id (file names.)
        while not self.process_id:
            self.parser.read_next_message()

        self.fd.seek(0)

    def read(self, length):
        if not length:
            return ''
        buf = self.fd.read(length)
        if not buf or len(buf) != length:
            raise EOFError()
        return buf

    def __iter__(self):
        #import inspect
        #log.debug('iter called by this guy: {0}'.format(inspect.stack()[1]))
        return self

    def __repr__(self):
        return "<ParseProcessLog log-path: %r>" % self._log_path

    def __nonzero__(self):
        return self.wait_for_lastcall()

    def reset(self):
        self.fd.seek(0)
        self.lastcall = None
        self.call_id = 0

    def compare_calls(self, a, b):
        """Compare two calls for equality. Same implementation as before netlog.
        @param a: call a
        @param b: call b
        @return: True if a == b else False
        """
        if a["api"] == b["api"] and \
                a["status"] == b["status"] and \
                a["arguments"] == b["arguments"] and \
                a["return"] == b["return"]:
            return True
        return False

    def wait_for_lastcall(self):
        while not self.lastcall:
            try:
                if not self.parser.read_next_message():
                    return False
            except EOFError:
                return False

        return True

    def next(self):
        if not self.fd:
            raise StopIteration()

        if not self.wait_for_lastcall():
            self.reset()
            raise StopIteration()

        nextcall, self.lastcall = self.lastcall, None

        self.wait_for_lastcall()
        while self.lastcall and self.compare_calls(nextcall, self.lastcall):
            nextcall["repeated"] += 1
            self.lastcall = None
            self.wait_for_lastcall()

        nextcall["id"] = self.call_id
        self.call_id += 1

        return nextcall

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        self.process_id, self.parent_id, self.process_name = pid, ppid, procname
        self.first_seen = timestring

    def log_thread(self, context, pid):
        pass

    def log_anomaly(self, subcategory, tid, funcname, msg):
        self.lastcall = dict(thread_id=tid, category="anomaly", api="",
                             subcategory=subcategory, funcname=funcname,
                             msg=msg)

    def log_call(self, context, apiname, category, arguments):
        apiindex, status, returnval, tid, timediff = context

        current_time = self.first_seen + datetime.timedelta(0, 0, timediff*1000)
        timestring = logtime(current_time)

        self.lastcall = self._parse([timestring,
                                     tid,
                                     category,
                                     apiname,
                                     status,
                                     returnval] + arguments)

    def log_error(self, emsg):
        log.warning("ParseProcessLog error condition on log %s: %s", str(self._log_path), emsg)

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        call = {}
        arguments = []

        try:
            timestamp = row[0]    # Timestamp of current API call invocation.
            thread_id = row[1]    # Thread ID.
            category = row[2]     # Win32 function category.
            api_name = row[3]     # Name of the Windows API.
            status_value = row[4] # Success or Failure?
            return_value = row[5] # Value returned by the function.
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(6, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:
                arg_name, arg_value = row[index]
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", row[index], e)
                continue

            argument["name"] = arg_name

            argument["value"] = convert_to_printable(cleanup_value(arg_value))
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["thread_id"] = str(thread_id)
        call["category"] = category
        call["api"] = api_name
        call["status"] = bool(int(status_value))

        if isinstance(return_value, int):
            call["return"] = "0x%.08x" % return_value
        else:
            call["return"] = convert_to_printable(cleanup_value(return_value))

        call["arguments"] = arguments
        call["repeated"] = 0

        return call

class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path):
        """@param  logs_path: logs path.
        """
        self._logs_path = logs_path
        self.cfg = Config()

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not os.path.exists(self._logs_path):
            log.warning("Analysis results folder does not exist at path \"%s\".", self._logs_path)
            return results

        # TODO: this should check the current analysis configuration and raise a warning
        # if injection is enabled and there is no logs folder.
        if len(os.listdir(self._logs_path)) == 0:
            log.info("Analysis results folder does not contain any file or injection was disabled.")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if os.path.isdir(file_path):
                continue

            # Skipping the current log file if it's too big.
            if os.stat(file_path).st_size > self.cfg.processing.analysis_size_limit:
                log.warning("Behavioral log {0} too big to be processed, skipped.".format(file_name))
                continue

            # Invoke parsing of current log file.
            current_log = ParseProcessLog(file_path)
            if current_log.process_id is None:
                continue

            # If the current log actually contains any data, add its data to
            # the results list.
            results.append({
                "process_id": current_log.process_id,
                "process_name": current_log.process_name,
                "parent_id": current_log.parent_id,
                "first_seen": logtime(current_log.first_seen),
                "calls": current_log.calls,
            })

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

class FileSystem(object):
    """file operations include: open, read, written, deleted, replaced """

    key = "filesystem"

    def __init__(self):
        self.opened = []
        self.read = []
        self.written = []
        self.deleted = []
        self.replaced = []
        self.fsfeature = []
        self.events = []
        self.filehandles = {}
        self.fseid = 0
    
    def process_call(self, call):
        """processing the logged api, and extract the file system 
        behaviors
        @return: file system behaviors json list 
        """
        def load_args(call):
            """ Get the key:value pair api arguments
            """
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res
    
        def generic_handle_details(self, call, item):
            """ 
            @return: 
            """
            event = None
            if call["api"] in item["apis"]:
                args = load_args(call)
                self.fseid += 1

                event = {
                    "operation": item["operation"],
                    "data": {}
                        }

                for argsym, argkey in item["args"]:
                    event["data"][argsym] = args.get(argkey)

                return event
        
        def generic_handle(self, data, call):
            """
            @return:
            """
            # iterate through the predefined template objects in gendat
            for item in data:
                event = generic_handle_details(self, call, item)
                if event:
                    return event

            return None

        def add_handle(handles, handle, filename):
            handles[handle] = filename

        def remove_handle(handles, handle):
            if handle in handles:
                handles.pop(handle)

        def get_handle(handles, handle):
            return handles.get(handle)

        event = None

        gendat = [
            {
                "operation": "open",
                "apis": [
                    "NtOpenFile",
                    "OpenFile",
                    ],
                "args": [ ("file", "FileName") ]
            },
            {
                "operation": "read",
                "apis": [
                    "NtReadFile",
                    "ReadFile",
                    ],
                "args": [("handle", "FileHandle")] 
            },
            {
                "operation": "write",
                "apis": [
                    "URLDownloadToFileW",
                    "URLDownloadToFileA",
                    "NtWriteFile"
                    ],
                "args": [("handle", "FileHandle")]
            },
            {
                "operation": "delete",
                "apis": [
                    "DeleteFileA",
                    "DeleteFileW",
                    "NtDeleteFile"
                    ],
                "args": [ ("file", "FileName") ]
            },
            {
                "operation": "replaced",
                "apis": [
                    "MoveFileWithProgressW",
                    "MoveFileExA",
                    "MoveFileExW"
                    ],
                "args": [ 
                    ("from", "ExistingFileName"),
                    ("to", "NewFileName")    
                ],
            },
        ]

        # obtained the syscall with the generic handle (not the file path
        # string)
        event = generic_handle(self, gendat, call) 
        args = load_args(call)

        # obtain the file path string from the generic handles
        if event:
            if call["api"] in ["NtReadFile","ReadFile","NtWriteFile"]: 
                event["data"]["file"] = get_handle(self.filehandles, args["FileHandle"])
            elif call["api"] in ["NtCreateFile", "NtOpenFile"]:
                add_handle(self.filehandles, args["FileHandle"], args["FileName"])
                event["data"]["file"] = args["FileName"] 
            elif call["api"] in ["CreateFileW"]:
                add_handle(self.filehandles, call["return"], args["FileName"])
                event["data"]["file"] = args["FileName"]
            elif call["api"] in ["NtClose", "CloseHandle"]:
                remove_handle(self.filehandles, args["handle"])

        return event

    def apicall_process(self, call, process):
        """call to the process_call method to get the fat 
        about the filesystem behaviors.
        """
        # event is one of the filesystem events we are desired.
        event = self.process_call(call)
        # add the returned event to its caterogies. 
        if event:
            if event["operation"] == "open":
                self.opened.append(event["data"]["file"])
            elif event["operation"] == "read":
                self.read.append(event["data"]["file"])
            elif event["operation"] == "write":
                self.written.append(event["data"]["file"])
            elif event["operation"] == "delete":
                self.deleted.append(event["data"]["file"])
            elif event["operation"] == "replaced":
                self.replaced.append(event["data"]["file"])

    def run(self):
        """ return the dictionary of properly formated filesystem behaviors
        """
        if self.opened:
            self.opened = list(set([x.lower() for x in self.opened if x]))

        if self.read:
            self.read = list(set([x.lower() for x in self.read if x]))

        if self.written:
            self.written = list(set([x.lower() for x in self.written if x]))
        
        if self.deleted:
            self.deleted = list(set([x.lower() for x in self.deleted if x]))
        
        if self.replaced:
            self.replaced = list(set([x.lower() for x in self.replaced if x]))

        try:
            fsfeature = {
                    "Opened files":self.opened, 
                    "Read files":self.read,
                    "Written files":self.written,
                    "Deleted files":self.deleted, 
                    "Replaced files":self.replaced
                }
        except:
            log.exception("Failed to create the fsfeature object.")

        return fsfeature

class Network:
    """network information include:
    TCP connections, DNS requrests, HTTP requests, UDP communications
    """
    key = "network"
    
    def __init__(self, analysis_path, task):
        self.analysis_path = analysis_path
        self.task = task
        self.results = {} 
        self.tcpdst = []
        self.udpdst = []
        self.dnssrv = []
        self.httpsrv = []

    def run(self):
        
        networkinfo = NetworkAnalysis()
        networkinfo.set_path(self.analysis_path)
        networkinfo.set_task(self.task)

        results = networkinfo.run() 

        # get the udp dst
        if results:
            for entry in results["udp"]:
                if entry:
                    if "192.168.56" not in entry["dst"]:
                        self.udpdst.append(entry["dst"])

            # get the tcp dst
            for entry in results["tcp"]:
                if entry: 
                    if "192.168.56" not in entry["dst"]:
                        self.tcpdst.append(entry["dst"])

            # get the DNS request
            for entry in results["dns"]:
                if entry: 
                    self.dnssrv.append(entry["request"])

            # get the http request
            for entry in results["http"]:
                if entry:
                    self.httpsrv.append(entry["dst"])
        
        self.results = {
                    "TCP connections": list(set(self.tcpdst)), 
                    "UDP connections": list(set(self.udpdst)),
                    "DNS requests": list(set(self.dnssrv)), 
                    "HTTP requests": list(set(self.httpsrv))
                }

        return self.results

class Mutexes:
    """mutexes information include:
    Created mutexes, Opened mutexes
    """
    key = "mutexes"

    def __init__(self):
        self.created = []
        self.opened = []

    def apicall_process(self, call, process):
        """ get the mutex info to the private variables.
        """
        if call["api"] == "NtOpenMutant":
            for argument in call["arguments"]:
                if argument["name"] == "MutexName":
                    value = argument["value"].strip()
                    if not value:
                        continue

                    if value not in self.opened:
                        self.opened.append(value)

        elif call["api"] == "NtCreateMutant":
            for argument in call["arguments"]:
                if argument["name"] == "MutexName":
                    value = argument["value"].strip()
                    if not value:
                        continue

                    if value not in self.created:
                        self.created.append(value)

    def run(self):
        """ return the created and opended mutexes.
        """
        try:
            mutexinfo = {
                    "Opened mutexes":list(set([x.lower() for x in self.opened if x])),
                    "Created mutexes":list(set([x.lower() for x in self.created if x])) 
                    }
        except:
            log.exception("Failed to create the mutexinfo object")

        return mutexinfo

class ProcInfo:
    """processes operation include:
    Created processes, Terminated processes
    """
    key = "procinfo"

    def __init__(self):
        self.processes = []
        self.tree = []
        self.created = []
        self.terminated = []
   
    def apicall_process(self, call, process):
        """Parse the log to generate a process tree.
        """
        for entry in self.processes:
            if entry["pid"] == process["process_id"]:
                return

        self.processes.append(dict(
            name=process["process_name"],
            pid=process["process_id"],
            parent_id=process["parent_id"],
            childre=[]
        ))
        
    def run(self):
        """Walk through the existing tree to get the generated children
        """

        #walk through the generated list of processes.
        for process in self.processes:
            has_parent = False
            #walk through the list again.
            for process_again in self.processes:
                #If we find a parent for the first process, we mark it as a child
                if process_again["pid"] == process["parent_id"]:
                    has_parent = True

            # If the process has a parent, add it to the created list.
            if has_parent:
                self.created.append(process["name"])

        try:
            procinfo = {
                    "Created processes": self.created,
                    "Terminated processes":self.terminated
                }
        except:
            log.exception("Failed to create the procinfo object")

        return procinfo 

class RunTimeDLL:
    """run time loaded DLLs:
    Runtime DLLs
    """
    key = "runtimedll"

    def __init__(self):
        self.dlls = []

    def add_loaded_module(self, name, base):
        """
        Add a loaded module to the internal database
        """
        self.modules[base] = name

    def get_loaded_module(self, base):
        """
        Get the name of a loaded module from the internal db
        """
        return self.modules.get(base, "")

    def process_call(self, call):
        """processing the logged api, and extract the file system 
        behaviors
        @return: file system behaviors json list 
        """
        def load_args(call):
            """ Get the key:value pair api arguments
            """
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res
    
        def generic_handle_details(self, call, item):
            """ 
            @return: 
            """
            event = None
            if call["api"] in item["apis"]:
                args = load_args(call)

                event = {
                    "operation": item["operation"],
                    "data": {}
                        }

                for argsym, argkey in item["args"]:
                    if argsym == "file":
                        event["data"][argsym] = args.get(argkey)

                return event
        
        def generic_handle(self, data, call):
            """
            @return:
            """
            # iterate through the predefined template objects in gendat
            for item in data:
                event = generic_handle_details(self, call, item)
                if event:
                    return event

            return None

        def add_handle(handles, handle, filename):
            handles[handle] = filename

        def remove_handle(handles, handle):
            if handle in handles:
                handles.pop(handle)

        def get_handle(handles, handle):
            return handles.get(handle)

        event = None

        gendat = [
            {
                "operation":"loaddll",
                "apis":[
                    "LoadLibraryA",
                    "LoadLibraryW",
                    "LoadLibraryExA",
                    "LoadLibraryExW",
                    "LdrLoadDll",
                    "LdrGetDllHandle"
                ],
                "args":[
                    ("file","FileName"),
                    ("pathtofile","PathToFile"),
                    ("moduleaddress","BaseAddress")
                ]
            }
        ]

        # obtained the syscall with the generic handle (not the file path
        # string)
        event = generic_handle(self, gendat, call) 
        args = load_args(call)

        # obtain the file path string from the generic handles
        if event:
            if call["api"] in ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                                "LoadLibraryExW", "LdrLoadDll", "LdrGetDllHandle"]:
                event["data"]["file"] =  args["FileName"]

        return event

    def apicall_process(self, call, process):
        """call to the process_call method to get the fat 
        about the filesystem behaviors.
        """
        # event is one of the filesystem events we are desired.
        event = self.process_call(call)
        # add the returned event to its caterogies. 
        if event:
            if event["operation"] == "loaddll":
                self.dlls.append(event["data"]["file"])
    
    def run(self):
        """
        """
        return {"Runtime DLLs": list(set([x.lower() for x in self.dlls]))}
            

class Service():
    """return the service info, hooking info
    """
    key = "service"

    def __init__(self):
        self.openedservices = []
        self.hook = []

    def process_call(self, call):
        """parse the argument from call"""
        
        def load_args(call):
            """ Get the key:value pair api arguments
            """
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res
     
        def generic_handle_details(self, call, item):
            """ 
            @return: 
            """
            event = None
            if call["api"] in item["apis"]:
                args = load_args(call)
                self.fseid += 1

                event = {
                    "operation": item["operation"],
                    "data": {}
                        }

                for argsym, argkey in item["args"]:
                    event["data"][argsym] = args.get(argkey)

                return event
        
        def generic_handle(self, data, call):
            """
            @return:
            """
            # iterate through the predefined template objects in gendat
            for item in data:
                event = generic_handle_details(self, call, item)
                if event:
                    return event

            return None

        # Generic handles
        def add_handle(handles, handle, filename):
            handles[handle] = filename

        def remove_handle(handles, handle):
            if handle in handles:
                handles.pop(handle)

        def get_handle(handles, handle):
            return handles.get(handle)


        event = None

        gendat = [
            {
                "operation": "service",
                "apis": [
                    "OpenServiceA",
                    "OpenServiceW"
                    ],
                "args": [ ("openedservice", "ServiceName") ]
            },
        ]

        # obtained the syscall with the generic handle (not the file path
        # string)
        event = generic_handle(self, gendat, call) 
        args = load_args(call)

        # obtain the file path string from the generic handles
        if event:
            if call["api"] in ["OpenServiceA","OpenServiceW"]: 
                add_handle(self.servicehandles, call["return"], args["ServiceName"])
                event["data"]["openedservice"] = args["ServiceName"]

        return event

    def apicall_process(self, call, process):
        """handling of api calls
        """
        # event is one of the service, or hooked events we are desired.
        event = self.process_call(call)
        # add the returned event to its caterogies. 
        if event:
            if event["operation"] == "service":
                self.openedservices.append(event["data"]["openedservice"])

    def run(self):

        return self.openedservices 


class VtFeatures(Processing):
    """generate the feature for matching the virustotal json file """

    key = "vtfeature"

    def run(self):
        """run the feature generation
        """
        behavior = {}

        vtfeature = {"id":File(self.file_path).get_sha256()}
        # get all the [pid].log
        behavior["processes"] = Processes(self.logs_path).run() 

        # feature categories
        instances = [
            FileSystem(),
            #Network(),
            Mutexes(),
            ProcInfo(),
            RunTimeDLL()
            #Misc(),
        ]

        network = Network(self.analysis_path, self.task)

        # Iterate calls and tell interested signatures about them
        for process in behavior["processes"]:
            for call in process["calls"]:
                for instance in instances:
                    try:
                        instance.apicall_process(call, process)
                    except:
                        log.exception("Failure in partial behavior \"%s\"", instance.key)

        for instance in instances:
            try:
                behavior[instance.key] = instance.run()
                vtfeature.update(behavior[instance.key])
            except:
                log.exception("Failed to run partial behavior class \"%s\"", instance.key)

            # Reset the ParseProcessLog instances after each module
            for process in behavior["processes"]:
                process["calls"].reset()

        # dealwith network info seperately
        behavior[network.key] = network.run()
        vtfeature.update(behavior[network.key])

        return vtfeature
