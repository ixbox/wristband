#!/usr/bin/env bash
# Creates the Cognito resources CognitoEmulatorTest needs in a running AWS Emulator
# and prints them as KEY=value lines (append to $GITHUB_ENV, or `export $(...)` locally).
#
# Requires the AWS CLI pointed at the emulator (AWS_ENDPOINT_URL, AWS_CA_BUNDLE,
# AWS_SHARED_CREDENTIALS_FILE, AWS_CONFIG_FILE, AWS_REGION); see the AWS Emulator user guide.
set -euo pipefail

suffix="$(date +%s)$RANDOM"
username="user-${suffix}@example.com"
password="Passw0rd!${suffix}"
domain="wristband-${suffix}"

pool=$(aws cognito-idp create-user-pool --pool-name "wristband-${suffix}" \
  --username-attributes email --auto-verified-attributes email \
  --query UserPool.Id --output text)
aws cognito-idp create-user-pool-domain --user-pool-id "$pool" --domain "$domain" >/dev/null
aws cognito-idp create-resource-server --user-pool-id "$pool" --identifier orders --name orders \
  --scopes ScopeName=read,ScopeDescription=read ScopeName=write,ScopeDescription=write >/dev/null

web=$(aws cognito-idp create-user-pool-client --user-pool-id "$pool" --client-name web \
  --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --query UserPoolClient.ClientId --output text)
read -r m2m_id m2m_secret < <(aws cognito-idp create-user-pool-client --user-pool-id "$pool" --client-name svc \
  --generate-secret --allowed-o-auth-flows client_credentials --allowed-o-auth-scopes orders/read \
  --allowed-o-auth-flows-user-pool-client \
  --query 'UserPoolClient.[ClientId,ClientSecret]' --output text)

aws cognito-idp admin-create-user --user-pool-id "$pool" --username "$username" \
  --user-attributes Name=email,Value="$username" Name=email_verified,Value=true \
  --message-action SUPPRESS >/dev/null
aws cognito-idp admin-set-user-password --user-pool-id "$pool" --username "$username" \
  --password "$password" --permanent

cat <<OUT
WRISTBAND_EMULATOR_ENDPOINT=${AWS_ENDPOINT_URL}
WRISTBAND_EMULATOR_CA=${AWS_CA_BUNDLE/#\~/$HOME}
WRISTBAND_EMULATOR_POOL=${pool}
WRISTBAND_EMULATOR_DOMAIN=${domain}
WRISTBAND_EMULATOR_WEB_CLIENT=${web}
WRISTBAND_EMULATOR_M2M_CLIENT=${m2m_id}
WRISTBAND_EMULATOR_M2M_SECRET=${m2m_secret}
WRISTBAND_EMULATOR_USERNAME=${username}
WRISTBAND_EMULATOR_PASSWORD=${password}
OUT
