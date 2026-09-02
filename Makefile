.PHONY: install-hooks

install-hooks:
	@mkdir -p .git/hooks
	@cp scripts/safety/precommit_no_samples.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit scripts/safety/precommit_no_samples.sh
	@echo "Installed .git/hooks/pre-commit from scripts/safety/precommit_no_samples.sh"
