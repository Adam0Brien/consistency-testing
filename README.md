export X_RH_IDENTITY='eyJpZGVudGl0eSI6eyJhY2NvdW50X251bWJlciI6IjEyMzQ1Iiwib3JnX2lkIjoiNjc4OTAiLCJ0eXBlIjoiVXNlciIsInVzZXIiOnsidXNlcm5hbWUiOiJ0ZXN0dXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInVzZXJfaWQiOiJ1c2VyLTEyMyJ9LCJpbnRlcm5hbCI6e319fQ=='


./smoke-check-consistency.sh \
  -f enabled \
  -e localhost:9081 \
  -u http://localhost:8081 \
  -c development-inventory-api-1 \
  -m smoke-check-consistency-matrix.yaml \
  -H "x-rh-identity: ${X_RH_IDENTITY}";
