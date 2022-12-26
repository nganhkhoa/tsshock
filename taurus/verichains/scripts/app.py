import sage.all as sg
import logging
from aiohttp import web
from _util import secp256k1_scalar_base_mult, SECP256K1_Q
import subprocess as sp

p = 0x03AFA33AFCCD44DDE8911926A41238B1DBB02F26A10059345BA3B7075CA016068DA30B93
Fp = sg.GF(p)
h1 = 0x01000000000000000000000000000400000000000000000001


def fp_log(g, h):
    ell = 55203145225092172882937151745333116390629453392100351661461466341434790533201579
    tried = 0
    while True:
        try:
            line = sp.check_output(
                f"/home/hh/tmp/cado-nfs/cado-nfs.py /home/hh/tmp/cado-session/p85.parameters_snapshot.0 target={h},{g}",
                shell=True)
            eh, eg = map(int, line.split(b','))
            e = int(sg.GF(ell)(eh) / eg)
            break
        except:  # sophisticated error from cado-nfs, simply retry
            h = h * g % p
            tried += 1

    order = sg.ZZ(sg.magma.Order(Fp(g) ** ell))
    return int(sg.crt([e, sg.discrete_log(Fp(h) ** ell, Fp(g) ** ell, ord=order)], [ell, order])) - tried


async def handle_recover_secret_key(request: web.Request) -> web.Response:
    data = await request.json()
    self_w = int(data['self_w'])
    zs = list(map(int, data['zs']))
    pkx = int(data['pkx'])
    print(self_w)
    print(zs)
    print(pkx)
    z = sg.reduce(lambda x, y: x * y % p, zs)
    x = (self_w + fp_log(h1 ** 2, z ** 2)) % SECP256K1_Q
    print(x)
    if secp256k1_scalar_base_mult(x)[0] == pkx:
        print("Recovered:", x)
    return web.json_response()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app = web.Application()
    app.add_routes([web.post('/recover-secret-key', handle_recover_secret_key)])
    web.run_app(app, port=1337, access_log_format='%a %t %Tf "%r" %s %b "%{Referer}i" "%{User-Agent}i"')
