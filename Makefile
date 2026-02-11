# Top-level upbx Makefile: unified version management across core and plugins.
# Updates VERSION?= in core/Makefile and plugin/*/Makefile via sed (portable: temp file + mv).

VERSION_MAKEFILES := core/Makefile $(wildcard plugin/*/Makefile)

# Sync version to all component Makefiles. Call from targets with version in VER.
# Usage: make set-version VERSION=x.y.z  OR  version-sync / version-bump-* (VER from core).
define version_sync
	@ver="$1"; \
	for f in $(VERSION_MAKEFILES); do \
		sed "s#^VERSION?=.*#VERSION?=$$ver#" "$$f" > "$$f.tmp" && mv "$$f.tmp" "$$f"; \
	done; \
	echo "Version set to $$ver in $(VERSION_MAKEFILES)"
endef

.PHONY: default set-version version-sync version-bump-patch version-bump-minor version-bump-major

default:
	@echo ""; \
	printf "%-40s %s\n" "COMPONENT" "VERSION"; \
	printf "%-40s %s\n" "----------------------------------------" "-------"; \
	for f in $(VERSION_MAKEFILES); do \
		component=$$(basename $$(dirname "$$f")); \
		version=$$(grep '^VERSION?=' "$$f" 2>/dev/null | sed 's/.*=//'); \
		printf "%-40s %s\n" "$$component" "$$version"; \
	done; \
	echo ""

set-version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make set-version VERSION=x.y.z"; exit 1; fi
	$(call version_sync,$(VERSION))

version-sync:
	@v=$$(grep '^VERSION?=' core/Makefile | sed 's/.*=//'); \
	if [ -z "$$v" ]; then echo "Could not read VERSION from core/Makefile"; exit 1; fi; \
	$(call version_sync,$$v)

version-bump-patch:
	@v=$$(grep '^VERSION?=' core/Makefile | sed 's/.*=//'); \
	maj=$$(echo "$$v" | cut -d. -f1); min=$$(echo "$$v" | cut -d. -f2); patch=$$(echo "$$v" | cut -d. -f3); \
	new="$$maj.$$min.$$((patch + 1))"; \
	$(call version_sync,$$new)

version-bump-minor:
	@v=$$(grep '^VERSION?=' core/Makefile | sed 's/.*=//'); \
	maj=$$(echo "$$v" | cut -d. -f1); min=$$(echo "$$v" | cut -d. -f2); \
	new="$$maj.$$((min + 1)).0"; \
	$(call version_sync,$$new)

version-bump-major:
	@v=$$(grep '^VERSION?=' core/Makefile | sed 's/.*=//'); \
	maj=$$(echo "$$v" | cut -d. -f1); \
	new="$$((maj + 1)).0.0"; \
	$(call version_sync,$$new)
