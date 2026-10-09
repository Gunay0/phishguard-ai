PRO_CREDITS = 20

def can_analyze(credits):
    return credits > 0

def use_credit(credits):
    if credits <= 0:
        return 0
    return credits - 1
