'''
Created on Aug 10, 2012


    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.

'''
import time
import logging

def print_timing(func):
    def wrapper(*arg, **kw):
        t1 = time.time()
        res = func(*arg, **kw)
        t2 = time.time()
        logging.info( '%s took %0.3f ms' % (func.__name__, (t2-t1)*1000.0))
        return res
    return wrapper


def eval_timing(func):
    def wrapper(*arg, **kw):
        t1 = time.time()
        res = func(*arg, **kw)
        t2 = time.time()
        logging.info( '%s took %0.9f ms' % (func.__name__, (t2-t1)*1000.0))
        return res
    return wrapper

