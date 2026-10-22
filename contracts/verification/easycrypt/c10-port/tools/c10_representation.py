#!/usr/bin/env python3
"""C10 representation: one closed typed expression tree, two language printers.

Counts are nonnegative integers (Lean Nat / EasyCrypt int restricted to >= 0).
This generator and the cross-tool interpretation of arithmetic, lists and ordered
tuples remain a disclosed TCB. The endpoint proofs are independently checked; this
is not a cross-kernel proof exporter. Default operation checks existing outputs.
Words use mathematical signed integers. Count subtraction is saturated at zero;
word subtraction is signed.
count division accepts only a positive constant divisor. Zero tests select between
branches of the same type. No machine arithmetic,
oracle, probability, arbitrary source injection, or cross-kernel export.
"""
from dataclasses import dataclass
from pathlib import Path
import argparse
import tempfile

COUNT = "count"
INT = "int"
def LIST(t): return ("list", t)
def PRODUCT(*ts): return ("product", *ts)
BYTES = LIST(INT)
NODES = LIST(BYTES)
LAYER = PRODUCT(NODES, INT, NODES)
SIGNATURE = PRODUCT(BYTES, NODES, LIST(NODES), LIST(LAYER))

@dataclass(frozen=True)
class Expr:
    op: str
    args: tuple
    ty: object

def var(name, ty): return Expr("var", (name,), ty)
def literal(n, ty=COUNT):
    assert type(n) is int and n >= 0 and ty in (COUNT, INT)
    return Expr("literal", (n,), ty)
def binary(op, a, b):
    assert op in ("add", "mul", "div", "mod", "pow")
    assert a.ty in (COUNT, INT)
    assert b.ty == (COUNT if op == "pow" else a.ty)
    assert op not in ("div", "mod") or a.ty == INT
    return Expr(op, (a,b), a.ty)
def add(a,b): return binary("add",a,b)
def mul(a,b): return binary("mul",a,b)
def reverse(bs):
    assert bs.ty[0] == "list"
    return Expr("reverse",(bs,),bs.ty)
def window(op, n, bs):
    assert op in ("take", "drop") and n.ty == COUNT and bs.ty[0] == "list"
    return Expr(op,(n,bs),bs.ty)
def take(n,bs): return window("take",literal(n) if type(n) is int else n,bs)
def drop(n,bs): return window("drop",literal(n) if type(n) is int else n,bs)
def seq(n, binder, body):
    assert n.ty == COUNT and binder.op == "var" and binder.ty == COUNT
    return Expr("seq",(n,binder,body),LIST(body.ty))
def fold(bs, item, acc, body, zero):
    assert bs.ty == LIST(item.ty) and item.op == acc.op == "var"
    assert acc.ty == body.ty == zero.ty
    return Expr("fold",(bs,item,acc,body,zero),acc.ty)
def product(*xs): return Expr("product",xs,PRODUCT(*(x.ty for x in xs)))
def items(ty, *xs):
    assert all(x.ty == ty for x in xs)
    return Expr("items",xs,LIST(ty))
def cat(*xs):
    assert xs and xs[0].ty[0] == "list" and all(x.ty == xs[0].ty for x in xs)
    return Expr("cat",xs,xs[0].ty)
def repeat(n, x):
    assert n.ty == COUNT
    return Expr("repeat",(n,x),LIST(x.ty))
def count_sub(a, b):
    assert a.ty == b.ty == COUNT
    return Expr("count_sub", (a,b), COUNT)
def int_sub(a, b):
    assert a.ty == b.ty == INT
    return Expr("int_sub", (a,b), INT)
def count_div(a, divisor):
    assert a.ty == COUNT and type(divisor) is int and divisor > 0
    return Expr("count_div", (a,literal(divisor)), COUNT)
def index(bs, i, default):
    assert bs.ty == LIST(default.ty) and i.ty == COUNT
    return Expr("index", (bs,i,default), default.ty)
def update(bs, i, value):
    assert bs.ty == LIST(value.ty) and i.ty == COUNT
    return Expr("update", (bs,i,value), bs.ty)
def if_zero(n, zero, nonzero):
    assert n.ty in (COUNT, INT) and zero.ty == nonzero.ty
    return Expr("if_zero", (n,zero,nonzero), zero.ty)

DEFS = []
def define(name, params, body):
    assert name not in [d[0] for d in DEFS]
    def bound(e, names):
        if e.op == "var": assert e.args[0] in names
        elif e.op == "seq":
            n,v,b = e.args; bound(n,names); bound(b,names|{v.args[0]})
        elif e.op == "fold":
            bs,v,a,b,z = e.args
            bound(bs,names); bound(z,names); bound(b,names|{v.args[0],a.args[0]})
        else:
            for x in e.args:
                if isinstance(x,Expr): bound(x,names)
    bound(body,{p.args[0] for p in params})
    DEFS.append((name,params,body))
    def call(*args):
        assert tuple(a.ty for a in args) == tuple(p.ty for p in params)
        return Expr("call",(name,*args),body.ty)
    return call

# The only shared algorithm specification. Both printers consume these nodes.
bs = var("bs",BYTES)
b, acc = var("b",INT), var("acc",INT)
n, off, width = var("n",COUNT), var("off",COUNT), var("width",COUNT)
i, t, l = (var(x,COUNT) for x in ("i","t","l"))
byte_word_le = define("byte_word_le",(bs,),
    fold(bs,b,acc,add(b,mul(literal(256,INT),acc)),literal(0,INT)))
byte_word = define("byte_word",(bs,),byte_word_le(reverse(bs)))
word_window = define("word_window",(bs,off,width),
    binary("mod",binary("div",byte_word(bs),binary("pow",literal(2,INT),off)),
           binary("pow",literal(2,INT),width)))
ht_field = define("ht_field",(bs,),word_window(bs,literal(143),literal(18)))
fors_field = define("fors_field",(bs,t),word_window(bs,mul(literal(11),t),literal(11)))
wots_field = define("wots_field",(bs,i),word_window(bs,mul(literal(3),i),literal(3)))
# Acceptance computations consume one digest, retaining its correlated fields.
wots_sum = define("wots_sum",(bs,),
    fold(seq(literal(43),i,wots_field(bs,i)),b,acc,add(b,acc),literal(0,INT)))
wots_target = define("wots_target",(),literal(205,INT))
fors_zero_field = define("fors_zero_field",(bs,),word_window(bs,literal(132),literal(11)))
read_nodes = define("word_nodes",(n,bs,off),
    seq(n,i,take(16,drop(add(off,mul(literal(16),i)),bs))))
word_layer = define("word_layer",(bs,off),product(
    read_nodes(literal(43),bs,off),
    byte_word(take(4,drop(add(off,literal(688)),bs))),
    read_nodes(literal(9),bs,add(off,literal(692)))))
word_decode = define("word_decode",(bs,),product(
    take(16,bs),read_nodes(literal(13),bs,literal(16)),
    seq(literal(12),t,read_nodes(literal(11),bs,add(literal(224),mul(literal(176),t)))),
    seq(literal(2),l,word_layer(bs,add(literal(2336),mul(literal(836),l))))))

# Hash inputs: equality is about the preimage, independently of SHA output.
seed, root, address, left, right, message, random, secret = (
    var(x,BYTES) for x in ("seed","root","address","left","right","message","random","secret"))
value, values, tail = var("value",BYTES), var("values",NODES), var("tail",BYTES)
nonce = var("nonce",INT)
pad_node = define("pad_node",(value,),cat(value,repeat(literal(16),literal(0,INT))))
u32_bytes = define("u32_bytes",(nonce,),reverse(seq(literal(4),i,
    binary("mod",binary("div",nonce,binary("pow",literal(2,INT),mul(literal(8),i))),literal(256,INT)))))
hmsg_preimage = define("hmsg_preimage",(seed,root,random,message),
    cat(seed,root,random,message,repeat(literal(32),literal(255,INT))))
th_preimage = define("th_preimage",(seed,address,value),cat(seed,address,value))
pair_preimage = define("pair_preimage",(seed,address,left,right),cat(seed,address,left,right))
multi_preimage = define("multi_preimage",(seed,address,values),
    cat(seed,address,fold(values,value,tail,cat(pad_node(value),tail),items(INT))))
wots_preimage = define("wots_preimage",(seed,address,message,nonce),
    cat(seed,address,message,repeat(literal(28),literal(0,INT)),u32_bytes(nonce)))
r_preimage = define("r_preimage",(secret,random,message,nonce),
    cat(secret,items(INT,*(literal(x,INT) for x in [82,95,103,114,105,110,100])),
        random,message,repeat(literal(28),literal(0,INT)),u32_bytes(nonce)))


# Full-width address fields and private derivation inputs share the same bytes.
u64_bytes = define("u64_bytes",(nonce,),reverse(seq(literal(8),i,
    binary("mod",binary("div",nonce,binary("pow",literal(2,INT),mul(literal(8),i))),literal(256,INT)))))
layer, tree, kind, kp, ci, cp, ha, ht, leaf = (
    var(x,INT) for x in ("layer","tree","kind","kp","ci","cp","ha","ht","leaf"))
address_words = define("address_words",(layer,tree,kind,kp,ci,cp,ha),
    cat(u32_bytes(layer),u64_bytes(tree),u32_bytes(kind),u32_bytes(kp),
        u32_bytes(ci),u32_bytes(cp),u32_bytes(ha)))
chain_index_words = define("chain_index_words",(address,ci),
    cat(take(20,address),u32_bytes(ci),drop(24,address)))
chain_position_words = define("chain_position_words",(address,cp),
    cat(take(24,address),u32_bytes(cp),drop(28,address)))
wots_private_preimage = define("wots_private_preimage",(secret,layer,tree,kp,ci),
    cat(secret,items(INT,*(literal(x,INT) for x in [119,111,116,115])),
        u32_bytes(layer),repeat(literal(24),literal(0,INT)),u64_bytes(tree),
        u32_bytes(kp),u32_bytes(ci)))
fors_private_preimage = define("fors_private_preimage",(secret,ht,tree,leaf),
    cat(secret,items(INT,*(literal(x,INT) for x in [102,111,114,115])),
        u32_bytes(ht),u32_bytes(tree),u32_bytes(leaf)))

# Shuffle inputs and exact descending Fisher-Yates schedule. Stream/order values
# are counts here: the endpoint proofs establish that actual bytes are in range.
label = var("label", BYTES)
shuffle_forest_label = define("shuffle_forest_label", (),
    items(INT,*(literal(x,INT) for x in b"fors")))
shuffle_layer_label = define("shuffle_layer_label", (layer,),
    if_zero(layer, items(INT,*(literal(x,INT) for x in b"wots-0\0")),
        items(INT,*(literal(x,INT) for x in b"wots-1\0"))))
shuffle_seed_preimage = define("shuffle_seed_preimage", (seed,label),
    cat(items(INT,*(literal(x,INT) for x in b"sphincs-c10-shuffle-v1")),seed,label))
shuffle_block_preimage = define("shuffle_block_preimage", (seed,nonce),
    cat(items(INT,*(literal(x,INT) for x in b"sphincs-c10-fisher-yates-v1")),seed,u32_bytes(nonce)))
lo, hi, bound = (var(x,COUNT) for x in ("lo","hi","bound"))
shuffle_choice = define("shuffle_choice", (lo,hi,bound),
    count_div(mul(add(mul(hi,literal(256)),lo),bound),65536))
order, stream = var("order",LIST(COUNT)), var("stream",LIST(COUNT))
j = var("j",COUNT)
shuffle_swap = define("shuffle_swap", (order,i,j),
    update(update(order,i,index(order,j,literal(0))),j,index(order,i,literal(0))))
pos = mul(literal(2),count_sub(count_sub(n,literal(1)),i))
choice = shuffle_choice(index(stream,pos,literal(0)),
                        index(stream,add(pos,literal(1)),literal(0)),add(i,literal(1)))
# foldr on [1,...,n-1] executes n-1 first and 1 last.
shuffle_order = define("shuffle_order", (n,stream),
    fold(seq(count_sub(n,literal(1)),i,add(i,literal(1))),i,order,
         shuffle_swap(order,i,choice),seq(n,i,i)))

# First accepted digest: zero denotes exhaustion; a positive slot is index + 1.
# The finite digest schedule is a mathematical input, not extra oracle queries.
digests, digest, slot = var("digests",NODES), var("digest",BYTES), var("slot",COUNT)
next_slot = if_zero(slot,literal(0),add(slot,literal(1)))
wots_first_slot = define("wots_first_slot", (digests,),
    fold(digests,digest,slot,
         if_zero(int_sub(wots_sum(digest),wots_target()),literal(1),next_slot),literal(0)))
fors_first_slot = define("fors_first_slot", (digests,),
    fold(digests,digest,slot,
         if_zero(fors_zero_field(digest),literal(1),next_slot),literal(0)))

def type_text(ty, lean):
    if ty == COUNT: return "Nat" if lean else "int"
    if ty == INT: return "Int" if lean else "int"
    if ty[0] == "list":
        return f"(List {type_text(ty[1],lean)})" if lean else f"({type_text(ty[1],lean)} list)"
    assert ty[0] == "product"
    return "(" + (" × " if lean else " * ").join(type_text(t,lean) for t in ty[1:]) + ")"

def render(e, lean):
    r = lambda x: render(x,lean)
    op, a = e.op,e.args
    if op == "var": return a[0]
    if op == "literal": return str(a[0])
    if op in ("add","mul","div","mod","pow"):
        symbol={"add":"+","mul":"*","div":"/" if lean else "%/",
                "mod":"%" if lean else "%%","pow":"^"}[op]
        return f"({r(a[0])} {symbol} {r(a[1])})"
    if op == "reverse": return f"(List.reverse {r(a[0])})" if lean else f"(rev {r(a[0])})"
    if op in ("take","drop"):
        return f"(List.{op} {r(a[0])} {r(a[1])})" if lean else f"({op} {r(a[0])} {r(a[1])})"
    if op == "seq":
        n,v,b = a
        return f"((List.range {r(n)}).map (fun {r(v)} => {r(b)}))" if lean else f"(mkseq (fun {r(v)} => {r(b)}) {r(n)})"
    if op == "fold":
        bs,v,acc,b,z = a
        return f"({'List.foldr' if lean else 'foldr'} (fun {r(v)} {r(acc)} => {r(b)}) {r(z)} {r(bs)})"
    if op == "product": return "(" + ", ".join(r(x) for x in a) + ")"
    if op == "items": return "[" + (", " if lean else "; ").join(r(x) for x in a) + "]"
    if op == "cat": return "(" + " ++ ".join(r(x) for x in a) + ")"
    if op == "repeat":
        return f"({'List.replicate' if lean else 'nseq'} {r(a[0])} {r(a[1])})"
    if op == "count_sub":
        return f"({r(a[0])} - {r(a[1])})" if lean else f"(max 0 ({r(a[0])} - {r(a[1])}))"
    if op == "int_sub":
        return f"({r(a[0])} - {r(a[1])})"
    if op == "count_div":
        return f"({r(a[0])} {'/' if lean else '%/'} {r(a[1])})"
    if op == "index":
        bs,i,default = a
        return f"(List.getD {r(bs)} {r(i)} {r(default)})" if lean else f"(nth {r(default)} {r(bs)} {r(i)})"
    if op == "update":
        return f"({'List.set' if lean else 'put'} {r(a[0])} {r(a[1])} {r(a[2])})"
    if op == "if_zero":
        return f"(if {r(a[0])} = 0 then {r(a[1])} else {r(a[2])})"
    if op == "call": return "(" + a[0] + " " + " ".join(r(x) for x in a[1:]) + ")"
    raise ValueError(op)

def source(lean):
    header="Generated by easycrypt/c10-port/tools/c10_representation.py. Do not edit. "
    header+="Counts range over nonnegative integers; words are signed integers."
    lines = (["/- " + header + " -/", "import Init", "namespace C10Representation"] if lean else
             ["(* " + header + " *)", "require import AllCore List IntDiv."])
    for name,params,body in DEFS:
        ps=" ".join(f"({p.args[0]} : {type_text(p.ty,lean)})" for p in params)
        lines.append(f"{'def' if lean else 'op'} {name} {ps} : {type_text(body.ty,lean)} {' :=' if lean else '='}\n  {render(body,lean)}{'' if lean else '.'}")
    if lean: lines.append("end C10Representation")
    return "\n\n".join(lines)+"\n"

def outputs(root):
    return {root.parents[1]/"extracted/Extracted/C10Representation.lean": source(True),
            root/"cdrafts-split/C10Representation.ec": source(False)}

def check_outputs(expected):
    for p, text in expected.items():
        if not p.is_file() or p.read_bytes() != text.encode():
            raise ValueError(f"generated representation missing or changed: {p}")

def self_test():
    for a, b in ((literal(1), literal(2)), (literal(1,INT), literal(2)),
                 (literal(1), literal(2,INT))):
        try: int_sub(a,b)
        except AssertionError: pass
        else: raise RuntimeError("signed subtraction accepted a count operand")
    signed = int_sub(literal(1,INT),literal(205,INT))
    if signed.ty != INT or any(render(signed,lean) != "(1 - 205)" for lean in (True,False)):
        raise RuntimeError("signed subtraction changed interpretation")
    with tempfile.TemporaryDirectory(prefix="c10-representation-") as tmp:
        expected={Path(tmp)/"C10Representation.lean":source(True),
                  Path(tmp)/"C10Representation.ec":source(False)}
        for p, text in expected.items(): p.write_text(text)
        check_outputs(expected)
        for p, text in expected.items():
            for mutation in (None, text.replace("256", "255", 1), text+"\n"):
                if mutation is None: p.unlink()
                else: p.write_text(mutation)
                try: check_outputs(expected)
                except ValueError: pass
                else: raise RuntimeError(f"fidelity control accepted drift: {p}")
                p.write_text(text)
        check_outputs(expected)
    print("PASS paired generation: exact positive; both missing/changed/extended outputs rejected")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write",action="store_true")
    parser.add_argument("--self-test",action="store_true")
    args=parser.parse_args()
    if args.self_test: self_test()
    expected=outputs(Path(__file__).resolve().parents[1])
    if args.write:
        for p, text in expected.items(): p.write_text(text)
    check_outputs(expected)
    print("PASS paired generation: both current outputs equal the common expression tree")
