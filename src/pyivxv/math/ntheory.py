def legendre(a, p):
    return pow(a, (p - 1) // 2, p)


# https://www.ctfrecipes.com/cryptography/general-knowledge/maths/modular-arithmetic/tonelli-shanks
def tonelli(a, p):
    assert legendre(a, p) == 1, "not a quadratic-residue"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(a, (p + 1) // 4, p)

    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break

    c = pow(z, q, p)
    r = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)

    m = s

    t2 = 0

    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r
