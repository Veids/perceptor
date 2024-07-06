from random import choice
from string import ascii_letters


def filter_random_variable():
    data = {}

    def _wrapper(var):
        if var not in data:
            data[var] = "".join(choice(ascii_letters) for _ in range(12))

        return data[var]

    return _wrapper

common_filter_random_variable = filter_random_variable()
