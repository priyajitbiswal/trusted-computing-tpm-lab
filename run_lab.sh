#!/usr/bin/env bash
# ==============================================================================
# CS4005: Trusted Computing and Security Models - CIA 2
# Student: Priyajit Biswal (Reg No: 23011102068)
# TPM-Based Secure Key Storage and Data Sealing
# ==============================================================================

set -e

echo "=== Step 0: Initializing Software TPM (swtpm) ==="
mkdir -p /tmp/tpm_lab && cd /tmp/tpm_lab
killall swtpm 2>/dev/null || true
rm -rf /tmp/mytpm && mkdir -p /tmp/mytpm

swtpm_setup --tpm2 --tpm-state /tmp/mytpm --createek
swtpm socket --tpm2 --tpmstate dir=/tmp/mytpm \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags not-need-init,startup-clear -d

export TPM2TOOLS_TCTI="swtpm:port=2321"
tpm2_startup -c

echo ""
echo "=== Task 1: Environment Setup and TPM Verification ==="
echo "1. Checking Fixed Properties:"
tpm2_getcap properties-fixed | head -n 12

echo ""
echo "2. Generating Hardware Random Bytes:"
tpm2_getrandom --hex 16

echo ""
echo "3. Reading Initial PCR State (SHA-256):"
tpm2_pcrread sha256:0,1,2,7,16

echo ""
echo "=== Task 2: TPM Key Creation and Data Sealing ==="
echo "1. Creating Secret Payload:"
echo "SECURE_DATA_PRIYAJIT_23011102068" > secret_payload.txt
cat secret_payload.txt

echo ""
echo "2. Creating Storage Primary Key:"
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

echo ""
echo "3. Extracting Clean PCR 16 State and Creating Policy:"
tpm2_pcrread sha256:16 -o pcr16_val.bin
tpm2_createpolicy --policy-pcr -l sha256:16 -f pcr16_val.bin -L pcr16.policy
echo "PCR Policy Digest:"
xxd -p pcr16.policy

echo ""
echo "4. Sealing Data to PCR Policy and Loading Context:"
tpm2_create -C primary.ctx -u sealed.pub -r sealed.priv -i secret_payload.txt -L pcr16.policy
tpm2_flushcontext -t
tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx

echo ""
echo "=== Task 3A: Data Unsealing under Matching Policy ==="
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypcr -S session.ctx -l sha256:16
tpm2_unseal -p session:session.ctx -c sealed.ctx -o unsealed_output.txt
tpm2_flushcontext session.ctx
echo "Successfully unsealed secret:"
cat unsealed_output.txt

echo ""
echo "=== Task 3B: Tamper Simulation and Rejection Demonstration ==="
echo "Extending PCR 16 with arbitrary measurement..."
tpm2_pcrextend 16:sha256=f1d2d2f924e986ac86fdf7b36c94bcdf32beec158525b6a3832c3bb47565ef02
echo "Updated PCR 16 value:"
tpm2_pcrread sha256:16

tpm2_flushcontext -t
tpm2_flushcontext -l
tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx

echo "Attempting unseal under tampered state (expected to fail):"
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policypcr -S session.ctx -l sha256:16

set +e
tpm2_unseal -p session:session.ctx -c sealed.ctx -o unsealed_tampered.txt
UNSEAL_STATUS=$?
set -e

tpm2_flushcontext session.ctx 2>/dev/null || true

if [ $UNSEAL_STATUS -ne 0 ]; then
    echo "SUCCESS: TPM rejected unsealing as expected due to policy check failure (0x99D)."
else
    echo "ERROR: Unsealing should have failed!"
fi

echo ""
echo "=== Lab Execution Completed Successfully ==="
