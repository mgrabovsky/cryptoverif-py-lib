default:
	@echo 'No default target set.'
	@echo
	@echo 'Available targets:'
	@echo '    clean -- remove NSPK and WLSK temporary files'

clean:
	-$(RM) keytbl id{A,B} {pk,sk}{A,B,S}
	-$(RM) wlsk_{id,{enc,mac}_key}

.PHONY: default clean

