"""Emit oracle input lines: name TAB surface TAB version TAB hex."""
OPS = {"minus": "99", "plus": "9a", "mul": "9c", "div": "9d", "mod": "9e", "min": "a1", "max": "a2"}
X = {
    "filterL": "b50506d90107057f",   # Filter(3L, x: Long => true)
    "filterI": "b50402d90107047f",   # Filter(1, x: Int => true)
    "filterB": "b50201d90107027f",   # Filter(1.toByte, x: Byte => true)
    "selOOB": "8c86020402040205",    # SelectField((1, 1), 5)
    "int": "0402", "long": "0504", "byte": "0201", "true": "7f",
}
PAIRS = [("filterL", "int"), ("int", "filterL"), ("filterI", "long"), ("long", "filterI"),
         ("filterB", "int"), ("int", "filterB"), ("filterL", "filterI"), ("selOOB", "filterL"),
         ("filterL", "selOOB"), ("filterL", "true"), ("true", "filterL"),
         ("int", "long"), ("long", "int"), ("byte", "int"), ("int", "int"), ("true", "int")]
bodies = []
for on, oc in OPS.items():
    for l, r in PAIRS:
        bodies.append((f"{on}-{l}-{r}", oc + X[l] + X[r]))
for on, oc in {"bitor": "f2", "bitand": "f3"}.items():
    for l, r in [("filterL", "long"), ("filterL", "int"), ("long", "filterL")]:
        bodies.append((f"{on}-{l}-{r}", oc + X[l] + X[r]))


def vlq(n):
    out = b""
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return (out + bytes([b])).hex()


for name, b in bodies:
    for v in range(4):
        print(f"{name}\tbody\t{v}\t{b}")
    tree_body = "d193" + b + "0500"
    for h in ["00", "08", "09", "0a", "0b"]:
        hexs = h + tree_body if h == "00" else h + vlq(len(tree_body) // 2) + tree_body
        print(f"{name}\ttree\t{h}\t{hexs}")
