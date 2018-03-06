.PHONY: compile cover test typecheck xref check doc
REBAR=./rebar3

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean

cover: test
	$(REBAR) cover

test: compile
	$(REBAR) as test do eunit

typecheck:
	$(REBAR) dialyzer

xref:
	$(REBAR) xref

doc:
	$(REBAR) edoc

check: test typecheck xref
