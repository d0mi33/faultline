SCENARIO ?= baseline
RUN ?= runs/latest-$(SCENARIO)

.PHONY: run all k8s-up k8s-run verify promptfoo langsmith clean
run:        ## one scenario locally (docker compose)
	python3 -m faultline.run --scenario $(SCENARIO)
all:        ## every scenario, summary table
	python3 -m faultline.run --all
k8s-up:     ## local kind cluster + images
	./scripts/cluster-up.sh
k8s-run:    ## one scenario in its own namespace
	python3 -m faultline.run --backend k8s --scenario $(SCENARIO)
verify:     ## prove a kept namespace is sealed: make verify NS=faultline-<id>
	./scripts/verify-isolation.sh $(NS)
promptfoo:  ## grade a run with promptfoo
	cd evals/promptfoo && PROMPTFOO_PYTHON=$(abspath dw/bin/python) PROMPTFOO_DISABLE_TELEMETRY=1 FAULTLINE_RUN_DIR=$(abspath $(RUN)) npx -y promptfoo@0.126.0 eval -c promptfooconfig.yaml --no-cache
langsmith:  ## push a run to LangSmith as an experiment
	python3 evals/langsmith_eval.py $(RUN)
clean:
	rm -rf runs/*
