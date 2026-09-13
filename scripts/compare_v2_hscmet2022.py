#!/usr/bin/env python3
"""Compare archived V2 raw samples with HSC-MET 2022 PKI->CLC raw samples."""
from __future__ import annotations
import argparse, csv, math, tempfile
from collections import defaultdict
from pathlib import Path

REQUIRED_COLUMNS={"run_id","commit","gmssl_commit","message_bytes","phase","iteration","ns"}
DEFAULT_SIZES=(20,128,1024,4096)
V2_PHASES=("online_signcrypt","sender_total","unsigncrypt")
HSCMET_PHASES=("hscmet2022_sender_signcrypt","hscmet2022_unsigncrypt")

def read_raw(path:Path)->list[dict[str,str]]:
    with path.open("r",newline="",encoding="utf-8-sig") as f:
        r=csv.DictReader(f)
        if r.fieldnames is None: raise ValueError(f"{path}: missing CSV header")
        missing=REQUIRED_COLUMNS.difference(r.fieldnames)
        if missing: raise ValueError(f"{path}: missing columns: {sorted(missing)}")
        rows=list(r)
    if not rows: raise ValueError(f"{path}: contains no benchmark samples")
    return rows

def identity(rows:list[dict[str,str]],label:str)->tuple[str,str,str]:
    ids={r["run_id"] for r in rows}; commits={r["commit"] for r in rows}; gm={r["gmssl_commit"] for r in rows}
    if len(ids)!=1 or len(commits)!=1 or len(gm)!=1: raise ValueError(f"{label}: expected one run_id, implementation commit, and GmSSL commit")
    return next(iter(ids)),next(iter(commits)),next(iter(gm))

def phase_means(rows:list[dict[str,str]],*,label:str,allowed_phases:tuple[str,...],expected_sizes:tuple[int,...],expected_n:int)->dict[tuple[int,str],float]:
    groups:dict[tuple[int,str],list[tuple[int,int]]]=defaultdict(list)
    for row in rows:
        phase=row["phase"]
        if phase not in allowed_phases: continue
        try: size=int(row["message_bytes"]); it=int(row["iteration"]); ns=int(row["ns"])
        except ValueError as exc: raise ValueError(f"{label}: malformed row {row}") from exc
        if size not in expected_sizes: continue
        if it<0 or ns<0: raise ValueError(f"{label}: negative field in row {row}")
        groups[(size,phase)].append((it,ns))
    expected={(s,p) for s in expected_sizes for p in allowed_phases}
    if set(groups)!=expected: raise ValueError(f"{label}: benchmark groups mismatch; missing={sorted(expected.difference(groups))}, extra={sorted(set(groups).difference(expected))}")
    means={}
    for key,samples in groups.items():
        if len(samples)!=expected_n: raise ValueError(f"{label}: group {key} has n={len(samples)}, expected {expected_n}")
        its=[i for i,_ in samples]
        if set(its)!=set(range(expected_n)): raise ValueError(f"{label}: group {key} has missing/duplicate iteration indices")
        means[key]=sum(ns for _,ns in samples)/expected_n
    return means

def compare(v2_rows:list[dict[str,str]],hsc_rows:list[dict[str,str]],*,expected_sizes:tuple[int,...]=DEFAULT_SIZES,expected_n:int=1000)->tuple[dict[str,str],list[dict[str,object]]]:
    v2_run,v2_commit,v2_gm=identity(v2_rows,"V2"); h_run,h_commit,h_gm=identity(hsc_rows,"HSC-MET")
    if v2_gm!=h_gm: raise ValueError(f"GmSSL commit mismatch: V2={v2_gm}, HSC-MET={h_gm}; same-library comparison required")
    v2=phase_means(v2_rows,label="V2",allowed_phases=V2_PHASES,expected_sizes=expected_sizes,expected_n=expected_n)
    hsc=phase_means(hsc_rows,label="HSC-MET",allowed_phases=HSCMET_PHASES,expected_sizes=expected_sizes,expected_n=expected_n)
    rows=[]
    for size in expected_sizes:
        vo=v2[(size,"online_signcrypt")]/1_000_000.0; vt=v2[(size,"sender_total")]/1_000_000.0; vu=v2[(size,"unsigncrypt")]/1_000_000.0
        hs=hsc[(size,"hscmet2022_sender_signcrypt")]/1_000_000.0; hu=hsc[(size,"hscmet2022_unsigncrypt")]/1_000_000.0
        if hs<=0 or hu<=0: raise ValueError("HSC-MET mean latency must be positive")
        rows.append({"message_bytes":size,"v2_online_ms":vo,"v2_sender_total_ms":vt,"v2_unsigncrypt_ms":vu,"hscmet_signcrypt_ms":hs,"hscmet_unsigncrypt_ms":hu,"online_reduction_pct":(hs-vo)/hs*100.0,"sender_total_delta_pct":(vt-hs)/hs*100.0,"unsigncrypt_delta_pct":(vu-hu)/hu*100.0})
    meta={"v2_run_id":v2_run,"v2_commit":v2_commit,"hscmet_run_id":h_run,"hscmet_commit":h_commit,"gmssl_commit":v2_gm,"hscmet_n":"2","hscmet_k":"2"}
    return meta,rows

def write_comparison(path:Path,meta:dict[str,str],rows:list[dict[str,object]])->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    fields=("v2_run_id","v2_commit","hscmet_run_id","hscmet_commit","gmssl_commit","hscmet_n","hscmet_k","message_bytes","v2_online_ms","v2_sender_total_ms","v2_unsigncrypt_ms","hscmet_signcrypt_ms","hscmet_unsigncrypt_ms","online_reduction_pct","sender_total_delta_pct","unsigncrypt_delta_pct")
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for row in rows:
            m=dict(meta); m.update(row); w.writerow(m)

def synthetic_rows(*,run_id:str,commit:str,gmssl_commit:str,phase_values:dict[str,list[int]],message_bytes:int=20)->list[dict[str,str]]:
    rows=[]
    for phase,vals in phase_values.items():
        for i,ns in enumerate(vals): rows.append({"run_id":run_id,"commit":commit,"gmssl_commit":gmssl_commit,"message_bytes":str(message_bytes),"phase":phase,"iteration":str(i),"ns":str(ns)})
    return rows

def self_test()->None:
    v2=synthetic_rows(run_id="v2-self",commit="v2-c",gmssl_commit="same",phase_values={"online_signcrypt":[500000,500000],"sender_total":[2000000,2000000],"unsigncrypt":[3000000,3000000]})
    h=synthetic_rows(run_id="hsc-self",commit="hsc-c",gmssl_commit="same",phase_values={"hscmet2022_sender_signcrypt":[1000000,1000000],"hscmet2022_unsigncrypt":[1500000,1500000]})
    meta,rows=compare(v2,h,expected_sizes=(20,),expected_n=2); r=rows[0]
    assert meta["gmssl_commit"]=="same" and meta["hscmet_n"]=="2" and meta["hscmet_k"]=="2"
    assert math.isclose(float(r["online_reduction_pct"]),50.0)
    assert math.isclose(float(r["sender_total_delta_pct"]),100.0) and math.isclose(float(r["unsigncrypt_delta_pct"]),100.0)
    with tempfile.TemporaryDirectory() as td:
        out=Path(td)/"comparison.csv"; write_comparison(out,meta,rows); txt=out.read_text(encoding="utf-8"); assert "online_reduction_pct" in txt and "hsc-self" in txt
    bad=synthetic_rows(run_id="hsc-bad",commit="hsc-c",gmssl_commit="different",phase_values={"hscmet2022_sender_signcrypt":[1000000,1000000],"hscmet2022_unsigncrypt":[1500000,1500000]})
    try: compare(v2,bad,expected_sizes=(20,),expected_n=2)
    except ValueError as exc: assert "GmSSL commit mismatch" in str(exc)
    else: raise AssertionError("GmSSL mismatch was not rejected")
    print("compare_v2_hscmet2022 self-test: ok")

def parse_sizes(text:str)->tuple[int,...]:
    vals=tuple(int(x.strip()) for x in text.split(",") if x.strip())
    if not vals or any(x<0 for x in vals) or len(set(vals))!=len(vals): raise argparse.ArgumentTypeError("sizes must be unique non-negative integers")
    return vals

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("--v2-raw",type=Path); p.add_argument("--hscmet-raw",type=Path); p.add_argument("--out",type=Path); p.add_argument("--expected-sizes",type=parse_sizes,default=DEFAULT_SIZES); p.add_argument("--expected-n",type=int,default=1000); p.add_argument("--self-test",action="store_true"); a=p.parse_args()
    if a.self_test: self_test(); return 0
    if a.v2_raw is None or a.hscmet_raw is None or a.out is None: p.error("--v2-raw, --hscmet-raw, and --out are required unless --self-test")
    if a.expected_n<=0: p.error("--expected-n must be positive")
    meta,rows=compare(read_raw(a.v2_raw),read_raw(a.hscmet_raw),expected_sizes=a.expected_sizes,expected_n=a.expected_n); write_comparison(a.out,meta,rows); print(f"wrote {len(rows)} comparison rows to {a.out}"); return 0
if __name__=="__main__": raise SystemExit(main())
