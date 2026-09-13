#!/usr/bin/env python3
"""Summarize raw Gong et al. 2025 PKI->CLC benchmark samples."""
from __future__ import annotations
import argparse, csv, math, statistics, tempfile
from collections import defaultdict
from pathlib import Path
from typing import Iterable

REQUIRED_COLUMNS={"run_id","commit","gmssl_commit","message_bytes","phase","iteration","ns"}
GONG_PHASES=("gong2025_sender_signcrypt","gong2025_unsigncrypt")
DEFAULT_SIZES=(20,128,1024,4096)

def nearest_rank(values:Iterable[int],q:float)->int:
    vals=sorted(values)
    if not vals: raise ValueError("empty sample")
    if not 0<q<=1: raise ValueError("quantile must be in (0,1]")
    return vals[math.ceil(q*len(vals))-1]

def read_raw(path:Path)->list[dict[str,str]]:
    with path.open("r",newline="",encoding="utf-8-sig") as f:
        r=csv.DictReader(f)
        if r.fieldnames is None: raise ValueError(f"{path}: missing CSV header")
        missing=REQUIRED_COLUMNS.difference(r.fieldnames)
        if missing: raise ValueError(f"{path}: missing columns: {sorted(missing)}")
        rows=list(r)
    if not rows: raise ValueError(f"{path}: contains no benchmark samples")
    return rows

def validate_identity(rows:list[dict[str,str]])->tuple[str,str,str]:
    ids={r["run_id"] for r in rows}; commits={r["commit"] for r in rows}; gm={r["gmssl_commit"] for r in rows}
    if len(ids)!=1 or len(commits)!=1 or len(gm)!=1:
        raise ValueError("raw CSV must contain exactly one run_id, implementation commit, and GmSSL commit")
    return next(iter(ids)),next(iter(commits)),next(iter(gm))

def summarize(rows:list[dict[str,str]],*,expected_sizes:tuple[int,...]|None=None,expected_n:int|None=None)->list[dict[str,object]]:
    validate_identity(rows)
    groups:dict[tuple[int,str],list[tuple[int,int]]]=defaultdict(list)
    for row in rows:
        try: size=int(row["message_bytes"]); it=int(row["iteration"]); ns=int(row["ns"])
        except ValueError as exc: raise ValueError(f"non-integer benchmark field in row: {row}") from exc
        if size<0 or it<0 or ns<0: raise ValueError(f"negative benchmark field in row: {row}")
        phase=row["phase"]
        if phase not in GONG_PHASES: raise ValueError(f"unexpected Gong phase: {phase!r}")
        groups[(size,phase)].append((it,ns))
    if expected_sizes is not None:
        expected={(s,p) for s in expected_sizes for p in GONG_PHASES}
        if set(groups)!=expected:
            raise ValueError(f"Gong groups mismatch; missing={sorted(expected.difference(groups))}, extra={sorted(set(groups).difference(expected))}")
    out=[]
    for (size,phase),samples in sorted(groups.items()):
        iterations=[i for i,_ in samples]
        if len(iterations)!=len(set(iterations)): raise ValueError(f"duplicate iteration in group {(size,phase)}")
        if set(iterations)!=set(range(len(iterations))): raise ValueError(f"iteration sequence for {(size,phase)} is not contiguous from zero")
        vals=[ns for _,ns in samples]
        if expected_n is not None and len(vals)!=expected_n: raise ValueError(f"group {(size,phase)} has n={len(vals)}, expected {expected_n}")
        out.append({"message_bytes":size,"phase":phase,"n":len(vals),"mean_ns":statistics.fmean(vals),"median_ns":statistics.median(vals),"stdev_ns":statistics.stdev(vals) if len(vals)>1 else 0.0,"p95_ns":nearest_rank(vals,0.95)})
    return out

def write_summary(path:Path,rows:list[dict[str,object]])->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    fields=("message_bytes","phase","n","mean_ns","median_ns","stdev_ns","p95_ns")
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

def self_test()->None:
    rows=[]
    values={(20,"gong2025_sender_signcrypt"):[10,20,30,40,100],(20,"gong2025_unsigncrypt"):[50,60,70,80,90]}
    for (size,phase),samples in values.items():
        for i,ns in enumerate(samples): rows.append({"run_id":"self","commit":"gong-self","gmssl_commit":"gmssl-self","message_bytes":str(size),"phase":phase,"iteration":str(i),"ns":str(ns)})
    result=summarize(rows,expected_sizes=(20,),expected_n=5); by={str(r["phase"]):r for r in result}; a=by["gong2025_sender_signcrypt"]
    assert a["n"]==5 and a["mean_ns"]==40.0 and a["median_ns"]==30 and a["p95_ns"]==100
    assert math.isclose(float(a["stdev_ns"]),statistics.stdev([10,20,30,40,100]))
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/"summary.csv"; write_summary(p,result); assert p.read_text(encoding="utf-8").startswith("message_bytes,phase,n,")
    print("summarize_gong2025 self-test: ok")

def parse_sizes(text:str)->tuple[int,...]:
    vals=tuple(int(x.strip()) for x in text.split(",") if x.strip())
    if not vals or any(x<0 for x in vals) or len(set(vals))!=len(vals): raise argparse.ArgumentTypeError("sizes must be unique non-negative integers")
    return vals

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--raw",type=Path); p.add_argument("--out",type=Path); p.add_argument("--expected-sizes",type=parse_sizes,default=DEFAULT_SIZES); p.add_argument("--expected-n",type=int,default=1000); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if a.self_test: self_test(); return 0
    if a.raw is None or a.out is None: p.error("--raw and --out are required unless --self-test is used")
    if a.expected_n<=0: p.error("--expected-n must be positive")
    result=summarize(read_raw(a.raw),expected_sizes=a.expected_sizes,expected_n=a.expected_n); write_summary(a.out,result); print(f"wrote {len(result)} summary groups to {a.out}"); return 0
if __name__=="__main__": raise SystemExit(main())
