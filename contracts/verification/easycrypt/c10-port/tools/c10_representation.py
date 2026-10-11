#!/usr/bin/env python3
"""C10 representation: one closed typed expression tree, two language printers.

Counts are nonnegative integers (Lean Nat / EasyCrypt int restricted to >= 0).
This generator and the cross-tool interpretation of arithmetic, lists and ordered
tuples remain a disclosed TCB. The endpoint proofs are independently checked; this
is not a cross-kernel proof exporter. Default operation checks existing outputs.
Words use mathematical signed integers. No subtraction, machine arithmetic,
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
