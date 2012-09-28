#!/usr/bin/python

'''Setup script for the wpactrl extension.'''
import distutils
from distutils.core import setup
from distutils.extension import Extension
#from py4a import patch_distutils
#patch_distutils()


ext = Extension(name = 'wpactrl', sources = ['wpa_ctrl.c', 'wpactrl.c'],
                extra_compile_args = ["-fno-strict-aliasing"])

setup(name = 'wpactrl', ext_modules = [ext],
      description = 'Python bindings for wpa_supplicant/hostapd ctrl socket.')
