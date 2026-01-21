# How to prepare

## Run Veraison

```terminal
source ~/veraison-deployment/env/env.bash
```

```terminal
export SESSION_NAME=veraison
veraison start-tmux $SESSION_NAME
tmux attach -t $SESSION_NAME
```

```terminal
export VERAISON_REPO=$HOME/kpro/veraison
$VERAISON_ROOT/bin/veraison cocli corim submit \
    --corim-file $VERAISON_REPO/services/end-to-end/input/psa-endorsements.cbor \
    --media-type 'application/corim-unsigned+cbor; profile="http://arm.com/psa/iot/1"' \
    --api-server "https://localhost:9443/endorsement-provisioning/v1/submit" \
    --ca-cert $VERAISON_ROOT/certs/provisioning.crt
```
