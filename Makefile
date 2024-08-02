VERSION=$(shell grep version monero/__init__.py | awk -F'"' '{ print $$2 }')

version:
	@echo "Version: $(VERSION)"

sha256-github: version
	@echo -n 'sha256:  '
	@curl -L -s https://github.com/DiosDelRayo/monero-python/archive/refs/tags/v$(VERSION).tar.gz | sha256sum | awk '{print $$1}'
