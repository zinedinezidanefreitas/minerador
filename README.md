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

1 git clone https://github.com/zinedinezidanefreitas/minerador.git
2 cd minerador
