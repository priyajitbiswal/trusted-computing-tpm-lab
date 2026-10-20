import os
import subprocess
import json
import time

LAB_DIR = "/mnt/c/Users/priya/Downloads/tc_cia2/tpm_lab"
os.makedirs(LAB_DIR, exist_ok=True)

def run_cmd(cmd, cwd=LAB_DIR, env=None, check=True):
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    full_env["TPM2TOOLS_TCTI"] = "swtpm:port=2321"
    
    print(f"\n>>> Running: {cmd}")
    res = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        env=full_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print(f"Exit code: {res.returncode}")
    if res.stdout:
        print(f"STDOUT:\n{res.stdout}")
    if res.stderr:
        print(f"STDERR:\n{res.stderr}")
    return res

# 1. Setup swtpm
print("=== Starting SWTPM ===")
subprocess.run("killall swtpm 2>/dev/null || true", shell=True)
os.makedirs("/tmp/mytpm", exist_ok=True)
subprocess.run("rm -rf /tmp/mytpm/*", shell=True)
subprocess.run("swtpm_setup --tpm2 --tpm-state /tmp/mytpm --createek", shell=True, check=True)
subprocess.run(
    "swtpm socket --tpm2 --tpmstate dir=/tmp/mytpm --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear -d",
    shell=True,
    check=True
)
time.sleep(1)

# Run TPM startup
run_cmd("tpm2_startup -c")

# Run Task 1: Environment Setup & Verification
task1_steps = [
    {
        "title": "TPM Capability & Fixed Properties Verification",
        "cmd": "tpm2_getcap properties-fixed | head -n 14"
    },
    {
        "title": "TPM Hardware Random Number Generation (TRNG)",
        "cmd": "tpm2_getrandom --hex 16"
    },
    {
        "title": "Platform Configuration Registers (PCRs) Initial Read",
        "cmd": "tpm2_pcrread sha256:0,1,2,7,16"
    }
]

task1_results = []
for step in task1_steps:
    r = run_cmd(step["cmd"])
    task1_results.append({
        "title": step["title"],
        "cmd": step["cmd"],
        "stdout": r.stdout,
        "stderr": r.stderr,
        "exit_code": r.returncode
    })

# Run Task 2: TPM Key Creation & Data Sealing
task2_steps = [
    {
        "title": "Create Secret Data Payload",
        "cmd": 'echo "SECURE_DATA_PRIYAJIT_23011102068" > secret_payload.txt && cat secret_payload.txt'
    },
    {
        "title": "Create Primary Key in Owner Hierarchy",
        "cmd": "tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx"
    },
    {
        "title": "Extract Target PCR 16 Reference State",
        "cmd": "tpm2_pcrread sha256:16 -o pcr16_val.bin"
    },
    {
        "title": "Calculate PCR Policy Digest for PCR 16",
        "cmd": "tpm2_createpolicy --policy-pcr -l sha256:16 -f pcr16_val.bin -L pcr16.policy && xxd -p pcr16.policy"
    },
    {
        "title": "Seal Secret Data Bound to PCR Policy",
        "cmd": "tpm2_create -C primary.ctx -u sealed.pub -r sealed.priv -i secret_payload.txt -L pcr16.policy"
    },
    {
        "title": "Load Sealed Object Context into TPM",
        "cmd": "tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx"
    }
]

task2_results = []
for step in task2_steps:
    r = run_cmd(step["cmd"])
    task2_results.append({
        "title": step["title"],
        "cmd": step["cmd"],
        "stdout": r.stdout,
        "stderr": r.stderr,
        "exit_code": r.returncode
    })

# Run Task 3: Unsealing & Policy Verification
task3_steps = [
    {
        "title": "Start Policy Session for Legitimate State",
        "cmd": "tpm2_startauthsession -S session.ctx --policy-session"
    },
    {
        "title": "Evaluate Current PCR 16 against Session",
        "cmd": "tpm2_policypcr -S session.ctx -l sha256:16"
    },
    {
        "title": "Successfully Unseal Data with Valid Policy",
        "cmd": "tpm2_unseal -p session:session.ctx -c sealed.ctx -o unsealed_success.txt && cat unsealed_success.txt"
    },
    {
        "title": "Flush Policy Session Context",
        "cmd": "tpm2_flushcontext session.ctx"
    },
    {
        "title": "Simulate System Tampering: Extend PCR 16 with Malicious Measurement",
        "cmd": "tpm2_pcrextend 16:sha256=f1d2d2f924e986ac86fdf7b36c94bcdf32beec158525b6a3832c3bb47565ef02"
    },
    {
        "title": "Verify Altered PCR 16 Digest",
        "cmd": "tpm2_pcrread sha256:16"
    },
    {
        "title": "Start New Policy Session for Tampered State",
        "cmd": "tpm2_startauthsession -S session.ctx --policy-session"
    },
    {
        "title": "Evaluate Tampered PCR 16 against Policy",
        "cmd": "tpm2_policypcr -S session.ctx -l sha256:16"
    },
    {
        "title": "Attempt Unsealing with Tampered Platform State (Expect Failure)",
        "cmd": "tpm2_unseal -p session:session.ctx -c sealed.ctx -o unsealed_fail.txt"
    },
    {
        "title": "Flush Second Policy Session Context",
        "cmd": "tpm2_flushcontext session.ctx"
    }
]

task3_results = []
for step in task3_steps:
    r = run_cmd(step["cmd"], check=False)
    task3_results.append({
        "title": step["title"],
        "cmd": step["cmd"],
        "stdout": r.stdout,
        "stderr": r.stderr,
        "exit_code": r.returncode
    })

# Save structured results
all_results = {
    "student": {
        "name": "Priyajit Biswal",
        "reg_no": "23011102068",
        "course": "CS4005: Trusted Computing and Security Models",
        "assignment": "CIA-2"
    },
    "task1": task1_results,
    "task2": task2_results,
    "task3": task3_results
}

with open(os.path.join(LAB_DIR, "execution_results.json"), "w") as f:
    json.dump(all_results, f, indent=2)

print("\n>>> All steps executed and results saved to execution_results.json! <<<")
