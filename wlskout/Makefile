CV := ~/builds/cryptoverif/cryptoverif -lib ~/builds/cryptoverif/default
DOCKER := /usr/bin/docker
PY := /usr/bin/python3

default: help

help:
	@echo 'Available targets:'
	@echo '    help -- this message'
	@echo '    impl -- export the Python implementation'
	@echo '    docker -- create Docker image and containers for testing'
	@echo '    keys -- generate keys for testing'
	@echo '    clean -- remove temporary and intermediate files'
	@echo '    clean-all -- clean + remove Docker image and containers'

impl: ../woolamsk.cv
	cd .. ; $(CV) -impl python -o wlskout woolamsk.cv

docker:
	$(DOCKER) build -q -t cv_wlsk .
	$(eval PARENT = $(shell realpath ..))
	$(DOCKER) create -it -v "$(PARENT)":/mnt/cv -w /mnt/cv/wlskout --expose=2666 -P \
		--name=wlsk_server cv_wlsk python server.py
	$(DOCKER) create -it -v "$(PARENT)":/mnt/cv -w /mnt/cv/wlskout --expose=2666 -P \
		--name=wlsk_responder --link=wlsk_server cv_wlsk python responder.py

keys:
	$(PY) keygen.py

clean:
	-$(RM) keytbl wlsk_{id,{enc,mac}_key} WLSK_*.py

clean-all:
	$(DOCKER) rm wlsk_{responder,server}
	$(DOCKER) rmi cv_wlsk
	$(MAKE) $(MAKEFLAGS) clean

.PHONY: clean clean-all default docker help impl

