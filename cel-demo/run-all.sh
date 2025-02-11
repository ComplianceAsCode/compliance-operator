# /bin/bash

oc apply -f cel-demo/01-custom-rule-cel.yaml
oc apply -f cel-demo/02-tp.yaml
oc apply -f cel-demo/03-ssb.yaml

