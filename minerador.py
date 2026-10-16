#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
minerador.py - Minerador Scrypt (Litecoin / Dogecoin) em CPU via Stratum.

Algoritmo: scrypt(N=1024, r=1, p=1), o mesmo usado por Litecoin e Dogecoin.
Funciona com qualquer pool Stratum scrypt (mining.subscribe / authorize /
notify / set_difficulty / submit).

Exemplos:
  python minerador.py --selftest
  python minerador.py --benchmark
  python minerador.py --coin ltc  --url litecoinpool.org:3333 --user SUACONTA.worker1 --password x
  python minerador.py --coin doge --url POOL_DOGE:PORTA --user SEU_ENDERECO_DOGE.worker1 --password x

Observacao: no litecoinpool.org a mineracao e "merged" - minerando LTC voce
tambem recebe DOGE, bastando configurar o endereco Dogecoin no painel da conta.

Requer Python 3.6+ com OpenSSL 1.1+ (hashlib.scrypt).
"""

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import queue
import socket
import struct
import sys
import threading
import time
from fractions import Fraction

# Dificuldade 1 do Stratum para scrypt: 0x0000ffff << 208 (== 0xffff << 224).
SCRYPT_DIFF1 = 0xFFFF << 224
USER_AGENT = "minerador.py/1.0"


# --------------------------------------------------------------------------
# Funcoes de hash
# --------------------------------------------------------------------------
def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def scrypt_pow(header80):
    """Hash de prova de trabalho Scrypt (N=1024, r=1, p=1) de um header de 80 bytes."""
    return hashlib.scrypt(header80, salt=header80, n=1024, r=1, p=1, dklen=32)


def fix_prevhash(prevhash_hex):
    """O Stratum envia o prevhash com cada palavra de 4 bytes invertida."""
    raw = bytes.fromhex(prevhash_hex)
    return b"".join(raw[i:i + 4][::-1] for i in range(0, 32, 4))


def difficulty_to_target(diff):
    if diff <= 0:
        diff = 1e-9
    target = int(Fraction(SCRYPT_DIFF1) / Fraction(diff))
    return min(target, (1 << 256) - 1)


def build_header76(job, en2_hex):
    coinbase = bytes.fromhex(job["coinb1"] + job["en1"] + en2_hex + job["coinb2"])
    root = sha256d(coinbase)
    for branch in job["branch"]:
        root = sha256d(root + bytes.fromhex(branch))
    return (
        bytes.fromhex(job["version"])[::-1]
        + job["prev"]
        + root
        + bytes.fromhex(job["ntime"])[::-1]
        + bytes.fromhex(job["nbits"])[::-1]
    )


# --------------------------------------------------------------------------
# Worker (processo de mineracao)
# --------------------------------------------------------------------------
def worker(wid, nworkers, jobq, resq, gen, hashes, stop):
    job = None
    while not stop.is_set():
        # pega o job mais recente da fila
        try:
            job = jobq.get(timeout=0.5)
            while True:
                job = jobq.get_nowait()
        except queue.Empty:
            pass
        if job is None or job["gen"] != gen.value:
            continue
        mine(wid, nworkers, job, resq, gen, hashes, stop)


def mine(wid, nworkers, job, resq, gen, hashes, stop):
    target = job["target"]
    en2size = job["en2size"]
    en2_mod = 256 ** en2size
    en2 = wid
    my_gen = job["gen"]
    pack = struct.pack
    while True:
        en2_hex = (en2 % en2_mod).to_bytes(en2size, "big").hex()
        header76 = build_header76(job, en2_hex)
        count = 0
        for nonce in range(0, 1 << 32):
            hdr = header76 + pack("<I", nonce)
            h = hashlib.scrypt(hdr, salt=hdr, n=1024, r=1, p=1, dklen=32)
            if int.from_bytes(h, "little") <= target:
                resq.put({
                    "job_id": job["job_id"],
                    "en2": en2_hex,
                    "ntime": job["ntime"],
                    "nonce": "%08x" % nonce,
                    "gen": my_gen,
                })
            count += 1
            if count == 64:
                hashes[wid] += count
                count = 0
                if gen.value != my_gen or stop.is_set():
                    return
        hashes[wid] += count
        en2 += nworkers  # espaco de nonce esgotado: proximo extranonce2


# --------------------------------------------------------------------------
# Cliente Stratum
# --------------------------------------------------------------------------
class Session(object):
    def __init__(self, host, port, user, password, jobqs, resq, gen):
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.jobqs, self.resq, self.gen = jobqs, resq, gen
        self.sock = None
        self.lock = threading.Lock()
        self.alive = True
        self.msg_id = 10
        self.pending = set()
        self.en1 = None
        self.en2size = 4
        self.diff = 1.0
        self.notify = None
        self.accepted = 0
        self.rejected = 0
        self.stale = 0
        self.current_job_id = None

    # --- rede ---
    def send(self, method, params, mid=None):
        if mid is None:
            self.msg_id += 1
            mid = self.msg_id
        data = json.dumps({"id": mid, "method": method, "params": params}) + "\n"
        with self.lock:
            self.sock.sendall(data.encode())
        return mid

    def connect(self):
        print("[*] Conectando em %s:%d ..." % (self.host, self.port))
        self.sock = socket.create_connection((self.host, self.port), timeout=30)
        self.sock.settimeout(600)
        self.send("mining.subscribe", [USER_AGENT], mid=1)
        self.send("mining.authorize", [self.user, self.password], mid=2)
        t = threading.Thread(target=self.reader, daemon=True)
        t.start()

    def reader(self):
        try:
            f = self.sock.makefile("r", encoding="utf-8", newline="\n")
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                self.handle(msg)
        except Exception as e:  # noqa
            print("[!] Conexao perdida: %s" % e)
        self.alive = False

    # --- mensagens ---
    def handle(self, msg):
        method = msg.get("method")
        if method == "mining.notify":
            self.notify = msg["params"]
            self.push_job()
        elif method == "mining.set_difficulty":
            self.diff = float(msg["params"][0])
            print("[*] Dificuldade da pool: %g" % self.diff)
            self.push_job()
        elif method == "mining.set_extranonce":
            self.en1 = msg["params"][0]
            self.en2size = int(msg["params"][1])
            self.push_job()
        elif method == "client.reconnect":
            print("[!] Pool pediu reconexao")
            self.alive = False
        elif method == "client.show_message":
            print("[pool] %s" % (msg["params"][0] if msg.get("params") else ""))
        elif method is None:
            self.handle_response(msg)

    def handle_response(self, msg):
        mid = msg.get("id")
        res, err = msg.get("result"), msg.get("error")
        if mid == 1:
            if err or not res:
                print("[!] Falha no subscribe: %s" % (err,))
                self.alive = False
                return
            self.en1 = res[1]
            self.en2size = int(res[2])
            print("[*] Subscribe ok (extranonce1=%s, extranonce2_size=%d)" % (self.en1, self.en2size))
            self.push_job()
        elif mid == 2:
            if res is True:
                print("[*] Autorizado como %s" % self.user)
            else:
                print("[!] Autorizacao negada: %s" % (err,))
                self.alive = False
        elif mid in self.pending:
            self.pending.discard(mid)
            if res is True:
                self.accepted += 1
                print("[+] Share ACEITO (%d aceitos / %d rejeitados)" % (self.accepted, self.rejected))
            else:
                self.rejected += 1
                print("[-] Share REJEITADO: %s (%d aceitos / %d rejeitados)" % (err, self.accepted, self.rejected))

    def push_job(self):
        if self.notify is None or self.en1 is None:
            return
        job_id, prev, c1, c2, branch, version, nbits, ntime, clean = self.notify[:9]
        job = {
            "job_id": job_id,
            "prev": fix_prevhash(prev),
            "coinb1": c1,
            "coinb2": c2,
            "branch": branch,
            "version": version,
            "nbits": nbits,
            "ntime": ntime,
            "en1": self.en1,
            "en2size": self.en2size,
            "target": difficulty_to_target(self.diff),
        }
        with self.gen.get_lock():
            self.gen.value += 1
            job["gen"] = self.gen.value
        self.current_job_id = job_id
        for q in self.jobqs:
            q.put(job)
        if clean:
            print("[*] Novo job %s (clean)" % job_id)

    def submit(self, res):
        if res["job_id"] != self.current_job_id:
            self.stale += 1
            return
        mid = self.send("mining.submit", [self.user, res["job_id"], res["en2"], res["ntime"], res["nonce"]])
        self.pending.add(mid)
        print("[>] Share encontrado (job %s, nonce %s), enviando..." % (res["job_id"], res["nonce"]))


def parse_url(url):
    url = url.replace("stratum+tcp://", "").replace("tcp://", "").strip("/")
    host, _, port = url.partition(":")
    return host, int(port or 3333)


def run_miner(args):
    host, port = parse_url(args.url)
    nthreads = args.threads or os.cpu_count() or 1
    ctx = mp.get_context("spawn") if sys.platform == "win32" else mp.get_context()
    gen = ctx.Value("L", 0)
    stop = ctx.Event()
    resq = ctx.Queue()
    hashes = ctx.Array("L", nthreads, lock=False)
    jobqs = [ctx.Queue() for _ in range(nthreads)]
    procs = []
    for i in range(nthreads):
        p = ctx.Process(target=worker, args=(i, nthreads, jobqs[i], resq, gen, hashes, stop), daemon=True)
        p.start()
        procs.append(p)

    print("=" * 60)
    print(" minerador.py - Scrypt CPU | moeda: %s | threads: %d" % (args.coin.upper(), nthreads))
    print("=" * 60)

    last_total, last_time = 0, time.time()
    start = time.time()
    try:
        while True:
            session = Session(host, port, args.user, args.password, jobqs, resq, gen)
            try:
                session.connect()
            except Exception as e:  # noqa
                print("[!] Erro de conexao: %s. Nova tentativa em 5s." % e)
                time.sleep(5)
                continue
            while session.alive:
                try:
                    res = resq.get(timeout=1)
                    session.submit(res)
                except queue.Empty:
                    pass
                now = time.time()
                if now - last_time >= 15:
                    total = sum(hashes)
                    rate = (total - last_total) / (now - last_time)
                    print("[~] %.2f H/s (%.3f kH/s) | aceitos %d | rejeitados %d | stale %d | %ds"
                          % (rate, rate / 1000.0, session.accepted, session.rejected,
                             session.stale, now - start))
                    last_total, last_time = total, now
            try:
                session.sock.close()
            except Exception:  # noqa
                pass
            print("[*] Reconectando em 5s ...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Encerrando ...")
    finally:
        stop.set()
        for p in procs:
            p.terminate()


# --------------------------------------------------------------------------
# Testes
# --------------------------------------------------------------------------
def selftest():
    # Bloco genese do Litecoin
    header = (
        struct.pack("<I", 1)
        + bytes(32)
        + bytes.fromhex("97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9")[::-1]
        + struct.pack("<III", 1317972665, 0x1E0FFFF0, 2084524493)
    )
    pow_got = scrypt_pow(header)[::-1].hex()
    pow_exp = "0000050c34a64b415b6b15b37f2216634b5b1669cb9a2e38d76f7213b0671e00"
    id_got = sha256d(header)[::-1].hex()
    id_exp = "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"
    ok = pow_got == pow_exp and id_got == id_exp
    print("PoW scrypt do genese LTC : %s" % pow_got)
    print("Esperado                 : %s" % pow_exp)
    print("Hash/ID (sha256d)        : %s" % id_got)
    print("Esperado                 : %s" % id_exp)
    print("RESULTADO                : %s" % ("OK" if ok else "FALHOU"))
    t = difficulty_to_target(1)
    print("Target diff 1      : %064x" % t)
    return 0 if ok else 1


def benchmark(seconds=5):
    header = bytes(76)
    n, t0 = 0, time.time()
    while time.time() - t0 < seconds:
        h = header + struct.pack("<I", n)
        hashlib.scrypt(h, salt=h, n=1024, r=1, p=1, dklen=32)
        n += 1
    rate = n / (time.time() - t0)
    cpus = os.cpu_count() or 1
    print("1 nucleo : %.1f H/s" % rate)
    print("%d nucleos (estimado): ~%.1f H/s" % (cpus, rate * cpus))


def main():
    ap = argparse.ArgumentParser(description="Minerador Scrypt (Litecoin/Dogecoin) em CPU via Stratum")
    ap.add_argument("--coin", choices=["ltc", "doge"], default="ltc", help="moeda (apenas informativo; o algoritmo e o mesmo)")
    ap.add_argument("--url", help="pool, ex.: litecoinpool.org:3333 ou stratum+tcp://host:porta")
    ap.add_argument("--user", help="usuario/carteira da pool (ex.: conta.worker ou endereco.worker)")
    ap.add_argument("--password", default="x", help="senha da pool (padrao: x)")
    ap.add_argument("--threads", type=int, default=0, help="numero de processos (padrao: todos os nucleos)")
    ap.add_argument("--selftest", action="store_true", help="valida o scrypt com o bloco genese do Litecoin")
    ap.add_argument("--benchmark", action="store_true", help="mede o hashrate da CPU")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.benchmark:
        benchmark()
        return
    if not args.url or not args.user:
        ap.error("--url e --user sao obrigatorios para minerar")
    run_miner(args)


if __name__ == "__main__":
    mp.freeze_support()
    main()
