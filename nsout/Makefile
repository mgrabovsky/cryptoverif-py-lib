CV := ~/builds/cryptoverif1.19/cryptoverif -lib ~/builds/cryptoverif1.19/default

default: help

help:
	@echo 'Available targets:'
	@echo '    help -- this message'
	@echo '    impl -- export the Python implementation'
	@echo '    test -- run the test script'
	@echo '    clean -- remove temporary and intermediate files'

impl: ../nspk3tbl.ocv
	cd .. ; $(CV) -impl python -o nsout nspk3tbl.ocv

test:
	./test.py

clean:
	-$(RM) id{A,B} {sk,pk}{A,B,S} keytbl ONS_*.py

.PHONY: clean default help impl test

