#!/usr/bin/env python3
import sys
import logging
import logging.handlers
import optparse

import csv
import fileinput
import itertools
import struct
import time

from functools import partial

import ipaddr
import pygeoip

cc_idx = dict((cc.lower(), i) for i,cc in enumerate(pygeoip.const.COUNTRY_CODES))
cc_idx['--'] = cc_idx['']
cc_idx['cw'] = cc_idx['an'] #netherlands antilles / curacao
cc_idx['uk'] = cc_idx['gb'] #uk / great britain
cc_idx['sx'] = cc_idx['fx'] #st. martin?

def init_logger(opts):
    level = logging.INFO
    handler = logging.StreamHandler()
    #handler = logging.handlers.SysLogHandler(address='/dev/log')
    if opts.debug:
        level = logging.DEBUG
        handler = logging.StreamHandler()
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

def parse_args(argv):
    if argv is None:
        argv = sys.argv[1:]
    p = optparse.OptionParser()

    cmdlist = []
    for cmd, (f, usage) in sorted(cmds.items()):
        cmdlist.append('%-8s\t%%prog %s' % (cmd, usage))
    cmdlist = '\n  '.join(cmdlist)

    p.usage = '%%prog [options] <cmd> <arg>+\n\nExamples:\n  %s' % cmdlist

    p.add_option('-d', '--debug', action='store_true',
            default=False, help="debug mode")
    p.add_option('-g', '--geoip', action='store_true',
            default=False, help='test with C GeoIP module')
    p.add_option('-w', '--write-dat', help='write filename.dat')
    p.add_option('-l', '--locations', help='city locations csv')
    opts, args = p.parse_args(argv)

    #sanity check
    if not args or args[0] not in cmds:
        p.error('missing command. choose from: %s' % ' '.join(sorted(cmds)))

    return opts, args


def test_dbs(opts, args):
    """test reference.dat and test.dat against a list of IPs and print any differences"""
    ref_file, tst_file = args[:2]
    gi_ref = pygeoip.GeoIP(ref_file, pygeoip.MEMORY_CACHE)
    gi_tst = pygeoip.GeoIP(tst_file, pygeoip.MEMORY_CACHE)
    dbtype = gi_ref._databaseType
    if gi_ref._databaseType != gi_tst._databaseType:
        print("error: database types don't match")
        exit(1)

    if opts.geoip:
        import GeoIP
        logging.debug('using GeoIP module')
        gi_ref = GeoIP.open(ref_file, pygeoip.MEMORY_CACHE)
        gi_tst = GeoIP.open(test_file, pygeoip.MEMORY_CACHE)
    else:
        logging.debug('using pygeoip module')

    isequal = lambda lhs, rhs: lhs == rhs
    if dbtype in (pygeoip.const.ASNUM_EDITION, pygeoip.const.ASNUM_EDITION_V6,
            pygeoip.const.ISP_EDITION, pygeoip.const.ORG_EDITION):
        get_ref = gi_ref.org_by_addr
        get_tst = gi_tst.org_by_addr
    elif dbtype in (pygeoip.const.CITY_EDITION_REV1, pygeoip.const.CITY_EDITION_REV1_V6):
        get_ref = gi_ref.record_by_addr
        get_tst = gi_tst.record_by_addr
        def isequal(lhs, rhs):
            if lhs and rhs:
                #Python's float rounding makes these unpredictable,
                #so just stomp them to ints as a sanity check.
                for k in ('latitude', 'longitude'):
                    lhs[k] = int(lhs[k])
                    rhs[k] = int(rhs[k])
            return lhs == rhs
    elif dbtype in (pygeoip.const.COUNTRY_EDITION, pygeoip.const.COUNTRY_EDITION_V6):
        get_ref = gi_ref.country_code_by_addr
        get_tst = gi_tst.country_code_by_addr
    else:
        print("error: unknown database type")
        exit(1)

    ok = bad = 0
    for ip in fileinput.input(args[2:]):
        ip = ip.strip()
        ref = get_ref(ip)
        tst = get_tst(ip)
        if not isequal(ref, tst):
            print(ip, ref, tst)
            bad += 1
        else:
            ok += 1
    print('ok:', ok, 'bad:', bad)
test_dbs.usage = 'test reference.dat test.dat ips.txt'


def dev(opts, args):
    cases = [
        # 1bit prefix then 2bit prefix (next level)
        (['128.0.0.0/1', '192.0.0.0/2'],
            ' 0 [\'--\', 1] 1 ["3 (\'1\',)", "5 (\'2\',)"]'),

        # 1bit prefix then 3bit prefix (two levels down)
        (['128.0.0.0/1', '160.0.0.0/3'],
            ' 0 [\'--\', 1] 1 [2, "4 (\'1\',)"] 2 ["4 (\'1\',)", "6 (\'3\',)"]'),

        # 2bit prefix then 3bit prefix (next level)
        (['128.0.0.0/2', '128.0.0.0/3'],
            ' 0 [\'--\', 1] 1 [2, \'--\'] 2 ["6 (\'3\',)", "4 (\'2\',)"]'),

        # 2bit prefix then 4bit prefix (two levels down)
        (['128.0.0.0/2', '144.0.0.0/4'],
            ' 0 [\'--\', 1] 1 [2, \'--\'] 2 [3, "5 (\'2\',)"] 3 ["5 (\'2\',)", "7 (\'4\',)"]'),
    ]
    def do_case(inputs, expected):
        print('+', inputs, expected)
        r = ASNRadixTree(debug=True)
        for snet in inputs:
            net = ipaddr.IPNetwork(snet)
            r[net] = (str(net.prefixlen),)
        dump = ''
        for node in r.segments:
            dump += ' ' + str(node.segment) + ' ' + \
                str([r.dump_node(node.child[0]), r.dump_node(node.child[1])])
        assert dump == expected
    for case in cases:
        do_case(*case)
    print('PASS')
dev.usage = ''


def gen_csv(f):
    """peek at rows from a csv and start yielding when we get past the comments
    to a row that starts with an int"""
    def startswith_int(row):
        try:
            int(row[0][0])
            return True
        except (ValueError, IndexError):
            return False

    cr = csv.reader(f)
    return itertools.dropwhile(lambda x: not startswith_int(x), cr)


def flatten_city(opts, args):
    """flatten MM blocks and locations CSVs into one file for easier editing"""
    id_loc = dict((row[0], row[1:]) for row in gen_csv(open(opts.locations)))
    cw = csv.writer(sys.stdout, lineterminator='\n')
    for row in gen_csv(fileinput.input(args)):
        row[-1:] = id_loc[row[-1]]
        cw.writerow(row)
flatten_city.usage = '-l GeoLiteCity-Location.csv flat GeoLiteCity-Blocks.csv > flatcity.csv'


class RadixTreeNode(object):
    __slots__ = ['segment', 'child']
    def __init__(self, segment):
        self.segment = segment
        self.child = [None, None]


class RadixTree(object):
    def __init__(self, debug=False):
        self.debug = debug

        self.netcount = 0
        self.segments = [RadixTreeNode(0)]
        self.data_offsets = {}
        self.data_segments = []
        self.cur_offset = 1

    def __setitem__(self, net, data):
        self.netcount += 1
        inet = int(net)
        node = self.segments[0]
        if self.debug:
            print('++', 'add', str(net))
        for depth in range(self.seek_depth, self.seek_depth - (net.prefixlen-1), -1):
            bit = (inet >> depth) & 1
            if self.debug:
                print('level %d direction %d isleaf %d nextdirection %d' %
                    (31 - depth, bit,
                    node.child[bit] != None and not isinstance(node.child[bit], RadixTreeNode),
                    (inet >> (depth - 1)) & 1))
            if not node.child[bit]: # does not exist
                node.child[bit] = RadixTreeNode(len(self.segments))
                self.segments.append(node.child[bit])
                if self.debug:
                    print('new node', node.child[bit].segment, '[\'--\', \'--\']')
            elif not isinstance(node.child[bit], RadixTreeNode): # exists as a leaf
                new = RadixTreeNode(len(self.segments))
                self.segments.append(new)
                next_bit = (inet >> (depth - 1)) & 1
                new.child[not next_bit] = node.child[bit]
                if depth > self.seek_depth - (net.prefixlen-2): # allow for new data leaf
                    new.child[next_bit] = node.child[bit]
                node.child[bit] = new
                if self.debug:
                    print('new node', new.segment,
                        [self.dump_node(new.child[0]), self.dump_node(new.child[1])])
            node = node.child[bit]

        if not data in self.data_offsets:
            self.data_offsets[data] = self.cur_offset
            enc_data = self.encode(*data)
            self.data_segments.append(enc_data)
            self.cur_offset += (len(enc_data))

        last_bit = (inet >> (self.seek_depth - (net.prefixlen-1))) & 1
        node.child[last_bit] = data
        if self.debug:
            print('attach data to node', node.segment,
                [self.dump_node(node.child[0]), self.dump_node(node.child[1])])

    def gen_nets(self, opts, args):
        raise NotImplementedError

    def load(self, opts, args):
        for nets, data in self.gen_nets(opts, args):
            for net in nets:
                self[net] = data

    def dump_node(self, node):
        if not node:
            #empty leaf
            return '--'
        elif isinstance(node, RadixTreeNode):
            #internal node
            return node.segment
        else:
            #data leaf
            data = node
            return '%d %s' % (len(self.segments) + self.data_offsets[data], node)

    def dump(self):
        for node in self.segments:
            print(node.segment, [self.dump_node(node.child[0]), self.dump_node(node.child[1])])

    def encode(self, *args):
        raise NotImplementedError

    def encode_rec(self, rec, reclen):
        """encode rec as 4-byte little-endian int, then truncate it to reclen"""
        assert(reclen <= 4)
        return struct.pack('<I', rec)[:reclen]

    def serialize_node(self, node):
        if not node:
            #empty leaf
            rec = len(self.segments)
        elif isinstance(node, RadixTreeNode):
            #internal node
            rec = node.segment
        else:
            #data leaf
            data = node[0] if self.debug else node
            rec = len(self.segments) + self.data_offsets[data]
        return self.encode_rec(rec, self.reclen)

    def serialize(self, f):
        if len(self.segments) >= 2 ** (8 * self.segreclen):
            logging.warning('too many segments for final segment record size!')

        for node in self.segments:
            f.write(self.serialize_node(node.child[0]))
            f.write(self.serialize_node(node.child[1]))

        f.write(b'\x2a') #So long, and thanks for all the fish!
        f.write(''.join(self.data_segments).encode())

        f.write(b'csv2dat.py') #.dat file comment - can be anything
        f.write(b'\xff\xff\xff')
        f.write(chr(self.edition).encode())
        print('len(segments) %d' % len(self.segments))
        f.write(self.encode_rec(len(self.segments), self.segreclen))


class ASNRadixTree(RadixTree):
    usage = '-w mmasn.dat mmasn GeoIPASNum2.csv'
    cmd = 'mmasn'
    seek_depth = 31
    edition = pygeoip.const.ASNUM_EDITION
    reclen = pygeoip.const.STANDARD_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH

    def gen_nets(self, opts, args):
        for lo, hi, asn in gen_csv(fileinput.input(args)):
            lo, hi = ipaddr.IPAddress(int(lo)), ipaddr.IPAddress(int(hi))
            nets = ipaddr.summarize_address_range(lo, hi)
            yield nets, (asn,)

    def encode(self, data):
        return data + '\0'


class ASNv6RadixTree(ASNRadixTree):
    usage = '-w mmasn6.dat mmasn6 GeoIPASNum2v6.csv'
    cmd = 'mmasn6'
    seek_depth = 127
    edition = pygeoip.const.ASNUM_EDITION_V6
    reclen = pygeoip.const.STANDARD_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH

    def gen_nets(self, opts, args):
        for lo, hi, asn in gen_csv(fileinput.input(args)):
            lo, hi = ipaddr.IPAddress(int(lo)), ipaddr.IPAddress(int(hi))
            nets = ipaddr.summarize_address_range(lo, hi)
            yield nets, (asn,)


class ISPRadixTree(ASNRadixTree):
    usage = '-w mmisp.dat mmisp GeoIPISP.csv'
    cmd = 'mmisp'
    seek_depth = 31
    edition = pygeoip.const.ISP_EDITION
    reclen = pygeoip.const.ORG_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH


class OrgRadixTree(ASNRadixTree):
    usage = '-w mmorg.dat mmorg GeoIPOrg.csv'
    cmd = 'mmorg'
    seek_depth = 31
    edition = pygeoip.const.ORG_EDITION
    reclen = pygeoip.const.ORG_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH


class CityRev1RadixTree(RadixTree):
    usage = '-w mmcity.dat [-l GeoLiteCity-Location.csv] mmcity GeoLiteCity-Blocks.csv'
    cmd = 'mmcity'
    seek_depth = 31
    edition = pygeoip.const.CITY_EDITION_REV1
    reclen = pygeoip.const.STANDARD_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH

    def gen_nets(self, opts, args):
        id_loc = None
        if opts.locations:
            id_loc = dict((row[0], row[1:]) for row in gen_csv(open(opts.locations)))

        for row in gen_csv(fileinput.input(args)):
            lo, hi = row[:2]
            loc = row[2:]
            if id_loc:
                loc = id_loc[loc[0]]
            lo, hi = ipaddr.IPAddress(int(lo)), ipaddr.IPAddress(int(hi))
            nets = ipaddr.summarize_address_range(lo, hi)
            yield nets, tuple(loc)

    def encode(self, country, region, city, postal_code, lat, lon, metro_code, area_code):
        def str2num(num, ntype):
            return ntype(num) if num else ntype(0)

        country = country.lower()
        lat, lon = round(str2num(lat, float), 4), round(str2num(lon, float), 4)
        metro_code, area_code = str2num(metro_code, int), str2num(area_code, int)

        buf = []
        try:
            buf.append(chr(cc_idx[country]))
        except KeyError:
            logging.warning("'%s': missing country. update pygeoip.const.COUNTRY_CODES?", country)
            buf.append(chr(cc_idx['']))
        buf.append('\0'.join((region, city, postal_code)))
        buf.append('\0')
        buf.append(self.encode_rec(int((lat + 180) * 10000), 3))
        buf.append(self.encode_rec(int((lon + 180) * 10000), 3))
        if (metro_code or area_code) and country == 'us':
            buf.append(self.encode_rec(metro_code * 1000 + area_code, 3))
        else:
            buf.append('\0\0\0')
        return ''.join(buf)


class CityRev1v6RadixTree(CityRev1RadixTree):
    usage = '-w mmcity6.dat mmcity6 GeoLiteCityv6.csv'
    cmd = 'mmcity6'
    seek_depth = 127
    edition = pygeoip.const.CITY_EDITION_REV1
    reclen = pygeoip.const.STANDARD_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH

    def gen_nets(self, opts, args):
        for row in gen_csv(fileinput.input(args)):
            lo, hi = row[2:4]
            lo, hi = ipaddr.IPAddress(int(lo)), ipaddr.IPAddress(int(hi))
            nets = ipaddr.summarize_address_range(lo, hi)
            #v6 postal_code is after lat/lon instead of before like v4
            country, region, city, lat, lon, postal_code, metro_code, area_code = row[4:]
            yield nets, (country, region, city, postal_code, lat, lon, metro_code, area_code)


class CountryRadixTree(RadixTree):
    usage = '-w mmcountry.dat mmcountry GeoIPCountryWhois.csv'
    cmd = 'mmcountry'
    seek_depth = 31
    edition = pygeoip.const.COUNTRY_EDITION
    reclen = pygeoip.const.STANDARD_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH

    def gen_nets(self, opts, args):
        for _, _, lo, hi, cc, _ in gen_csv(fileinput.input(args)):
            lo, hi = ipaddr.IPAddress(int(lo)), ipaddr.IPAddress(int(hi))
            nets = ipaddr.summarize_address_range(lo, hi)
            yield nets, (cc,)

    def encode(self, cc):
        #unused
        return ''

    def serialize_node(self, node):
        if not node:
            #empty leaf
            rec = pygeoip.const.COUNTRY_BEGIN
        elif isinstance(node, RadixTreeNode):
            #internal node
            rec = node.segment
        else:
            #data leaf
            data = node[0] if self.debug else node
            cc = data[0]
            try:
                offset = cc_idx[cc.lower()]
            except KeyError:
                logging.warning("'%s': missing country. update pygeoip.const.COUNTRY_CODES?", cc)
                offset = 0
            #data leaves directly encode cc index as an offset
            rec = pygeoip.const.COUNTRY_BEGIN + offset
        return self.encode_rec(rec, self.reclen)

    def serialize(self, f):
        for node in self.segments:
            f.write(self.serialize_node(node.child[0]))
            f.write(self.serialize_node(node.child[1]))

        f.write(chr(0x00) * 3)
        f.write('csv2dat.py') #.dat file comment - can be anything
        f.write(chr(0xFF) * 3)
        f.write(chr(self.edition))
        f.write(self.encode_rec(len(self.segments), self.segreclen))


class Countryv6RadixTree(CountryRadixTree):
    usage = '-w mmcountry6.dat mmcountry6 GeoIPv6.csv'
    cmd = 'mmcountry6'
    seek_depth = 127
    edition = pygeoip.const.COUNTRY_EDITION_V6
    reclen = pygeoip.const.STANDARD_RECORD_LENGTH
    segreclen = pygeoip.const.SEGMENT_RECORD_LENGTH

    def gen_nets(self, opts, args):
        for row in gen_csv(fileinput.input(args)):
            #handle weird space before quote problems
            lo, hi, cc = [x.strip(' "') for x in row[2:5]]
            lo, hi = ipaddr.IPAddress(int(lo)), ipaddr.IPAddress(int(hi))
            nets = ipaddr.summarize_address_range(lo, hi)
            yield nets, (cc,)


def build_dat(RTree, opts, args):
    tstart = time.time()
    r = RTree(debug=opts.debug)

    r.load(opts, args)

    if opts.debug:
        r.dump()

    with open(opts.write_dat, 'wb') as f:
        r.serialize(f)

    tstop = time.time()
    print('wrote %d-node trie with %d networks (%d distinct labels) in %d seconds' % (
            len(r.segments), r.netcount, len(r.data_offsets), tstop - tstart))


rtrees = [
    ASNRadixTree, ASNv6RadixTree,
    CityRev1RadixTree, CityRev1v6RadixTree,
    CountryRadixTree, Countryv6RadixTree,
    ISPRadixTree, OrgRadixTree,
]
cmds = dict((rtree.cmd, (partial(build_dat, rtree), rtree.usage)) for rtree in rtrees)
cmds['flat'] = (flatten_city, flatten_city.usage)
cmds['test'] = (test_dbs, test_dbs.usage)
cmds['dev'] = (dev, dev.usage)

def main(argv=None):
    global opts
    opts, args = parse_args(argv)
    init_logger(opts)
    logging.debug(opts)
    logging.debug(args)

    cmd = args.pop(0)
    cmd, usage = cmds[cmd]
    return cmd(opts, args)


if __name__ == '__main__':
    rval = main()
    logging.shutdown()
    sys.exit(rval)

