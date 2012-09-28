# Makefile for pwifi listener

# pwifi header files used to import #defines for our python code
PWIFI_HDRS += ../So-Fi_c/src/pwifi/pwifi_common.h
PWIFI_HDRS += ../So-Fi_c/src/pwifi/pwifi_ipc.h

python-imports:
	python h2py.py $(PWIFI_HDRS)

.PHONY: clean
clean:
	-rm -f *.o

