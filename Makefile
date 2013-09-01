.PHONY: all
all: src/jquery.oauth.js

%.js: %.coffee
	cat $< | coffee -c -s > $@

