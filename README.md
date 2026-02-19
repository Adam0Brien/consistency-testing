This projects purpose is to test the consistency modes of the different Check endpoints in Kessel-Inventory

In order to run this you must have Inventory-api running with the config [full-setup-relations-ready.yaml](https://github.com/Adam0Brien/consistency-testing/blob/master/full-setup-relations-ready.yaml)

```
make inventory-up-relations-ready

```
aswell as the inventory consumer running and relations api


relations api
```
make relations-api-up
```
inventory-consumer
```
make inventory-consumer-up
```


Then you will need a X_RH_IDENTITY header exported to your terminal. 


export X_RH_IDENTITY='eyJpZGVudGl0eSI6eyJhY2NvdW50X251bWJlciI6IjEyMzQ1Iiwib3JnX2lkIjoiNjc4OTAiLCJ0eXBlIjoiVXNlciIsInVzZXIiOnsidXNlcm5hbWUiOiJ0ZXN0dXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInVzZXJfaWQiOiJ1c2VyLTEyMyJ9LCJpbnRlcm5hbCI6e319fQ=='


./smoke-check-consistency.sh \
  -f enabled \
  -e localhost:9081 \
  -u http://localhost:8081 \
  -c development-inventory-api-1 \
  -m smoke-check-consistency-matrix.yaml \
  -H "x-rh-identity: ${X_RH_IDENTITY}";
