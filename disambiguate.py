#!/usr/bin/env python3
import sys
import time
import ipaddress
import pygeoip

debug = False

def parse_args(argv):
    if argv is None:
        argv = sys.argv[1:]
    usage = 'disambiguate.py in.txt out.txt'
    if len(sys.argv) != 3:
        print(usage)
        return [], 1
    return sys.argv[1:], 0

def unit_test():
    cases = [
        # 1bit prefix then 2bit prefix (next level)
        (['8000::/1', 'C000::/2'],
            " ['x', 'i'] ['1', '2']"),

        # 1bit prefix then 3bit prefix (two levels down)
        (['8000::/1', 'A000::/3'],
            " ['x', 'i'] ['i', '1'] ['1', '3']"),
        
        # 2bit prefix then 3bit prefix (next level)
        (['8000::/2', '8000::/3'],
            " ['x', 'i'] ['i', 'x'] ['3', '2']"),

        # 2bit prefix then 4bit prefix (two levels down)
        (['8000::/2', '9000::/4'],
            " ['x', 'i'] ['i', 'x'] ['i', '2'] ['2', '4']"),
    ]
    def do_case(inputs, expected):
        print('+', inputs, expected)
        t = Tree()
        for snet in inputs:
            net = ipaddress.ip_network(snet)
            t[net] = str(net.prefixlen)
        dump = ''
        for node in t.segments:
            dump += ' ' + \
                str([t.dump_node(node.child[0]), t.dump_node(node.child[1])])
        print(dump)
        assert dump == expected
    for case in cases:
        do_case(*case)
    print('PASS')
    return 0

class Node(object):
    __slots__ = ['child']
    def __init__(self):
        self.child = [None, None]

class Tree(object):
    def __init__(self):
        self.net_count = 0
        self.segments = [Node()]
        self.seek_depth = 127

    def __setitem__(self, net, asn):
        self.net_count += 1
        prefix = int(net.network_address)
        node = self.segments[0]
        #debug = debug or (len(str(net)) == 8 and str(net)[6] == '/') # unit test
        #debug = debug or (len(str(net.network_address)) > 8 and str(net.network_address)[0:6] == '2a00:2' and net.prefixlen >= 20)
        if debug:
            print('++', 'add', str(net))
        for depth in range(self.seek_depth, self.seek_depth - (net.prefixlen-1), -1):
            bit = (prefix >> depth) & 1
            if debug:
                print('level %d direction %d isleaf %d nextdirection %d' %
                    (127 - depth, bit,
                    node.child[bit] != None and not isinstance(node.child[bit], Node),
                    (prefix >> (depth - 1)) & 1))
            if not node.child[bit]: # does not exist
                node.child[bit] = Node()
                self.segments.append(node.child[bit])
                if debug:
                    print('new node', '[\'--\', \'--\']')
            elif not isinstance(node.child[bit], Node): # exists as a leaf
                new = Node()
                self.segments.append(new)
                next_bit = (prefix >> (depth - 1)) & 1
                new.child[not next_bit] = node.child[bit]
                if depth > self.seek_depth - (net.prefixlen-2): # allow for new data leaf
                    new.child[next_bit] = node.child[bit]
                node.child[bit] = new
                if debug:
                    print('new node',
                        [self.dump_node(new.child[0]), self.dump_node(new.child[1])])
            node = node.child[bit]

        last_bit = (prefix >> (self.seek_depth - (net.prefixlen-1))) & 1
        node.child[last_bit] = asn
        if debug:
            print('attach data to node',
                [self.dump_node(node.child[0]), self.dump_node(node.child[1])])

    def load(self, prefixes):
        for net, asn in prefixes.iterate():
            self[net] = asn

    def dump_node(self, node):
        if not node: # empty leaf
            return 'x'
        elif isinstance(node, Node): # internal node
            return 'i'
        else: # data leaf
            return str(node[0])

    def dump(self):
        for node in self.segments:
            print([self.dump_node(node.child[0]), self.dump_node(node.child[1])])

class List(object):
    def __init__(self):
        self.net_count = 0
        self.levels = [[] for _ in range(129)]

    def load(self, args):
        for net, asn in self.gen_nets(args):
            l = net.prefixlen
            self.levels[l].append((net, asn))

    def gen_nets(self, args):
        for net_str, asn in self.gen_txt(args):
            net = ipaddress.ip_network(net_str)
            yield net, asn
            self.net_count += 1

    def gen_txt(self, args):
        with open(args[0]) as file:
            for line in file.readlines():
                yield line.strip().split()

    def iterate(self):
        for l in range(len(self.levels)):
            for net, asn in self.levels[l]:
                yield net, asn

    def reload(self, tree):
        node = tree.segments[0]
        self.visit_node(node, 0, 0)

    def visit_node(self, node, prefix, level):
        if not node: # empty leaf
            return
        if isinstance(node, Node): # internal node
            self.visit_node(node.child[0], prefix, level + 1)
            self.visit_node(node.child[1], prefix | (1 << (127 - level)), level + 1)
        else: # data leaf
            asn = node
            net = ipaddress.IPv6Network((prefix, level))
            self.levels[level].append((net, asn))
            self.net_count += 1

    def write_net(self, net, asn, file):
        file.write('%s %s\n' % (net, asn))

    def write(self, file):
        for net, asn in self.iterate():
            self.write_net(net, asn, file)

def disambiguate(args):
    tstart = time.time()

    # read in prefixes and sort into bins by length (level)
    p = List()
    p.load(args)
    print(p.net_count, 'input prefixes')

    # populate search tree with prefixes from shortest (widest subnet)
    # to longest (narrowest subnet), removing overlaps
    t = Tree()
    t.load(p)
    print(len(t.segments), 'nodes', t.net_count, 'networks')

    # traverse overlap-free tree back into list, relabeling any split prefixes
    p = List()
    p.reload(t)
    print(p.net_count, 'output prefixes')

    with open(args[1], 'w') as f:
        p.write(f)

    tstop = time.time()
    print('%d seconds elapsed' % (tstop - tstart))

def main(argv=None):
    #return unit_test()
    args, ret = parse_args(argv)
    if ret != 0:
        return ret
    return disambiguate(args)

if __name__ == '__main__':
    sys.exit(main())
