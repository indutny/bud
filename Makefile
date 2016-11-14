all:
	@echo "run \`make publish\` to publish package"
	@exit 1

publish:
	rm -rf bin/ && mkdir bin && touch bin/bud
	npm publish

.PHONY: all publish
