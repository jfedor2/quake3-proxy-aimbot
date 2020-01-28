NYT = 256


def reverse_bit_order(value):
    return sum(((value & 1 << i) >> i) << (7 - i) for i in range(8))


class Node:

    def __init__(self, symbol=None, parent=None, left=None, right=None, number=None, weight=0):
        self.symbol = symbol
        self.parent = parent
        self.left = left
        self.right = right
        self.number = number
        self.weight = weight


class Huffman:

    def __init__(self):
        self.nyt = Node(NYT, number=0)
        self.root = self.nyt
        self.node_for_symbol = {NYT: self.nyt}
        self.adapt = True
        self.nodes = []

    def emit_code_for(self, node, buffer, child=None):
        if node.parent:
            self.emit_code_for(node.parent, buffer, node)
        if child:
            buffer.write_bit(0 if child is node.left else 1)

    def find_leader(self, node):
        index = node.number
        while index >= 0 and self.nodes[index].weight == node.weight:
            index -= 1
        return self.nodes[index + 1]

    def swap_nodes(self, node1, node2):
        self.nodes[node1.number], self.nodes[node2.number] = node2, node1
        node1.number, node2.number = node2.number, node1.number
        node1.parent, node2.parent = node2.parent, node1.parent

        for (node_a, node_b) in ((node1, node2), (node2, node1)):
            if node_a.parent.left is node_b:
                node_a.parent.left = node_a
            else:
                node_a.parent.right = node_a

    def insert(self, symbol):
        node = self.node_for_symbol.get(symbol)

        if node is None:
            internal = Node()
            internal.weight = 1
            internal.left = self.nyt

            node = Node(symbol)
            node.weight = 1
            node.parent = internal

            internal.right = node

            internal.parent = self.nyt.parent
            if internal.parent is not None:
                internal.parent.left = internal
            else:
                self.root = internal

            self.nyt.parent = internal

            self.node_for_symbol[symbol] = node

            internal.number = len(self.nodes)
            self.nodes.append(internal)
            node.number = len(self.nodes)
            self.nodes.append(node)
            self.nyt.number = len(self.nodes)

            node = internal.parent

        while node is not None:
            leader = self.find_leader(node)

            if leader is not node and leader is not node.parent:
                self.swap_nodes(node, leader)

            node.weight += 1
            node = node.parent

    def encode(self, symbol, buffer):
        if symbol in self.node_for_symbol:
            self.emit_code_for(self.node_for_symbol[symbol], buffer)
        else:
            if not self.adapt:
                raise Exception("new symbol in non-adapting mode")
            self.emit_code_for(self.nyt, buffer)
            buffer.write_bits(symbol, 8)
        if self.adapt:
            self.insert(symbol)

    def decode(self, buffer, length):
        output = b''
        node = self.root
        while len(output) < length:
            if node.symbol is not None:
                if node.symbol == NYT:
                    if not self.adapt:
                        raise Exception("reached NYT in non-adapting mode")
                    value = reverse_bit_order(buffer.read_raw_bits(8))
                    output += bytes([value])
                    self.insert(value)
                else:
                    output += bytes([node.symbol])
                    if self.adapt:
                        self.insert(node.symbol)
                node = self.root
            else:
                if buffer.read_bit() == 0:
                    node = node.left
                else:
                    node = node.right
        return output

    def init_from_saved_tree(self, tree):
        for i in range(len(tree)):
            self.nodes.append(Node(number=i))
        # NYT is conceptually at the end of the list
        self.nyt.number = len(self.nodes)
        for i, n in enumerate(tree):
            if n <= 0:
                self.nodes[i].symbol = -n
                self.node_for_symbol[self.nodes[i].symbol] = self.nodes[i]
            else:
                self.nodes[i].left = (self.nyt if n == self.nyt.number else self.nodes[n])
                self.nodes[i].left.parent = self.nodes[i]
                self.nodes[i].right = self.nodes[n - 1]
                self.nodes[i].right.parent = self.nodes[i]
        # the weights weren't saved so we must switch to non-adaptive mode
        self.adapt = False
        self.root = self.nodes[0]

    def save_tree(self):
        return [-n.symbol if n.symbol is not None else n.left.number for n in self.nodes]


# negative value (and zero) means leaf, value is -symbol
# positive value means internal node, value is index ("number") of left child
# (right child's index is always value-1)
# that is enough to reconstruct the tree if we don't care about the weights
SAVED_TREE = [
    2, 4, 6, 8, 10, 0, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48,
    50, 52, 54, 56, -1, 58, 60, 62, 64, 66, -8, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92,
    -7, -128, 94, 96, -32, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, -13, 120, 122, 124,
    126, 128, 130, 132, 134, 136, 138, 140, 142, -104, 144, 146, 148, 150, -255, 152, 154, 156, 158,
    160, 162, 164, -195, 166, 168, -254, 170, 172, 174, 176, 178, -48, 180, 182, 184, 186, 188, -11,
    190, 192, 194, -12, 196, 198, 200, 202, -131, 204, 206, 208, 210, 212, -127, -16, 214, 216, 218,
    220, -116, 222, -10, -129, -232, -196, 224, 226, 228, 230, 232, 234, 236, 238, -66, 240, -3,
    242, -130, 244, 246, -9, 248, 250, 252, -67, 254, 256, 258, 260, -125, 262, -2, -126, 264, -101,
    -65, -6, -117, 266, -50, -124, -64, 268, 270, -132, 272, -138, 274, -118, -137, -136, 276, -114,
    -135, 278, 280, 282, 284, 286, 288, -120, 290, -123, -111, 292, 294, -52, 296, 298, -122, 300,
    -49, -29, -133, 302, 304, 306, 308, -194, 310, 312, 314, 316, 318, 320, 322, 324, -112, 326,
    328, -115, 330, -14, 332, -119, 334, 336, -53, 338, 340, -69, 342, -5, -121, 344, -4, -68, 346,
    -102, 348, -134, 350, -97, 352, 354, -113, -110, 356, -139, -31, -192, 358, 360, 362, 364, 366,
    -47, -199, 368, -95, 370, -108, -237, 372, -105, 374, 376, 378, 380, -103, -30, -99, -109, 382,
    384, -51, -100, 386, -92, 388, -56, 390, -94, 392, 394, -98, 396, 398, 400, -140, 402, 404, -96,
    406, 408, 410, 412, 414, 416, 418, 420, 422, 424, -193, 426, 428, -106, -72, 430, 432, 434, -76,
    436, 438, 440, 442, 444, 446, -143, 448, 450, 452, -54, 454, 456, 458, 460, -93, 462, 464, 466,
    468, 470, -58, 472, -200, -57, 474, 476, -144, 478, 480, -224, 482, -225, -55, 484, 486, 488,
    490, -142, 492, -61, 494, -15, -80, 496, -46, -24, 498, -40, -160, 500, -141, -107, -62, -34,
    -19, 502, -168, -176, 504, -17, 506, -91, -18, 508, -90, -71, -146, -70, 510, -208, -147, -240,
    -74, -88, -197, -78, -198, -234, -158, -28, -83, -82, -172, -150, -77, -26, -152, -156, -22,
    -148, -89, -174, -21, -63, -79, -162, -87, -42, -184, -84, -230, -33, -182, -86, -170, -154,
    -27, -145, -190, -73, -23, -60, -236, -228, -186, -203, -220, -216, -178, -151, -222, -20, -164,
    -210, -188, -81, -166, -204, -246, -207, -39, -214, -35, -173, -206, -175, -218, -25, -253,
    -191, -38, -212, -36, -205, -242, -180, -171, -149, -155, -202, -238, -248, -37, -161, -250,
    -153, -209, -159, -252, -213, -183, -226, -75, -85, -44, -229, -233, -157, -244, -167, -231,
    -59, -235, -169, -177, -165, -239, -221, -189, -211, -179, -187, -181, -41, -201, -163, -215,
    -217, -185, -43, -227, -223, -249, -219, -245, -251, -45, -241, -243, 512, -247
]

fixed_decoder = Huffman()
fixed_decoder.init_from_saved_tree(SAVED_TREE)
