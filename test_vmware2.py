import subprocess
import os

VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX_PATH = r"E:\SandBox\ShieldAI_Sandbox.vmx"
VM_USER = "sandbox"
VM_PASS = "123456"

print("--- Testing VIX Command ---")
cmd1 = ["/bin/bash", "-c", "echo 'Hello Malware' > /tmp/testlog.txt && chmod 777 /tmp/testlog.txt"]
r1 = subprocess.run([VMRUN_PATH, "-T", "ws", "-gu", VM_USER, "-gp", VM_PASS, "runProgramInGuest", VMX_PATH] + cmd1, capture_output=True, text=True)
print("RUN CMD STDOUT:", r1.stdout.strip())
print("RUN CMD STDERR:", r1.stderr.strip())

print("\n--- Testing Copy ---")
r2 = subprocess.run([VMRUN_PATH, "-T", "ws", "-gu", VM_USER, "-gp", VM_PASS, "copyFileFromGuestToHost", VMX_PATH, "/tmp/testlog.txt", "testlog.txt"], capture_output=True, text=True)
print("COPY STDOUT:", r2.stdout.strip())
print("COPY STDERR:", r2.stderr.strip())

if os.path.exists("testlog.txt"):
    with open("testlog.txt", "r") as f:
        print("FILE CONTENT:", f.read().strip())
else:
    print("FILE NOT COPIED")
