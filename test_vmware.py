import subprocess

VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
VMX_PATH = r"E:\SandBox\ShieldAI_Sandbox.vmx"
VM_USER = "sandbox"
VM_PASS = "123456"

print("--- Checking VMware Tools State ---")
r = subprocess.run([VMRUN_PATH, "-T", "ws", "checkToolsState", VMX_PATH], capture_output=True, text=True)
print("STDOUT:", r.stdout.strip())
print("STDERR:", r.stderr.strip())

print("\n--- Trying to Authenticate and Check Directory ---")
r = subprocess.run([VMRUN_PATH, "-T", "ws", "-gu", VM_USER, "-gp", VM_PASS, "directoryExistsInGuest", VMX_PATH, "/tmp"], capture_output=True, text=True)
print("STDOUT:", r.stdout.strip())
print("STDERR:", r.stderr.strip())
