"""
Module checks a random number to be prime
using Miller–Rabin primality test
"""

import random


def is_prime(n:int, k:int=40) -> bool:
    """
    Miller–Rabin primality test

    Arguments:
    :param n: potentianl prime number, int
    :param k: number of iterations for test, int
    """

    if not isinstance(n, int) or not isinstance(k, int) or k < 1 or n < 0:
        raise ValueError('Invalid input')

    if n in (2, 3):
        return True

    if n < 2 or n%2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    random_range = random.SystemRandom()
    for _ in range(k):
        base = random_range.randint(2, n - 1)
        x = pow(base, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True
