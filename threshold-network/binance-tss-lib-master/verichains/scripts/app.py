import dataclasses
from typing import Dict
from exploiter_square import Exploiter, SquareExploiter
import logging
from aiohttp import web
from _util import secp256k1_scalar_base_mult

exploiters: Dict[int, Exploiter] = {}


async def handle_gen_params(request: web.Request) -> web.Response:
    k = int(request.query.get("dlog_proof_repeat", "128"))
    exploiter = SquareExploiter(k)
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
    print("Public key:", secp256k1_scalar_base_mult(private_key))
    return web.json_response({"shares": shares, "private_key": private_key})


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app = web.Application()
    app.add_routes([web.get('/params', handle_get_params)])
    app.add_routes([web.get('/gen-params', handle_gen_params)])
    app.add_routes([web.post('/recover-shares', handle_recover_shares)])
    web.run_app(app, port=1337)
