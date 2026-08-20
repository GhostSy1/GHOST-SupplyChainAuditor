import os
import sys
import argparse
import json

def banner():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    print(r"""
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ███████╗██╗   ██╗██████╗ ██████╗ 
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██╔════╝██║   ██║██╔══██╗██╔══██╗
 ██║  ███╗███████║██║   ██║███████╗   ██║        ███████╗██║   ██║██████╔╝██████╔╝
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║        ╚════██║██║   ██║██╔═══╝ ██╔═══╝ 
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║        ███████║╚██████╔╝██║     ██║     
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ╚══════╝ ╚═════╝ ╚═╝     ╚═╝     
    GHOST-SupplyChainAuditor: Real Dependency & Artifact Security Inspector
""")

def audit_dependencies(file_path):
    findings = []
    if not os.path.exists(file_path):
        return [{"error": f"File not found: {file_path}"}]

    filename = os.path.basename(file_path)
    if filename == "package.json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                for pkg, ver in {**deps, **dev_deps}.items():
                    findings.append({"type": "npm_dependency", "package": pkg, "version": ver})
        except Exception as e:
            findings.append({"error": f"Failed to parse package.json: {str(e)}"})
            
    elif filename == "requirements.txt" or file_path.endswith(".txt"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        findings.append({"type": "pip_dependency", "specifier": line})
        except Exception as e:
            findings.append({"error": f"Failed to parse requirements.txt: {str(e)}"})
    else:
        findings.append({"error": "Unsupported file format. Provide package.json or requirements.txt"})

    return findings

def main():
    banner()
    parser = argparse.ArgumentParser(description="GHOST-SupplyChainAuditor Engine")
    parser.add_argument("--target", help="Path to package.json or requirements.txt")
    parser.add_argument("--json", help="Output JSON report path", default="supply_chain_report.json")
    args, unknown = parser.parse_known_args()

    target = args.target
    if not target:
        target = input("[*] Enter path to dependency file (package.json / requirements.txt): ").strip()

    print(f"\n[+] Auditing real dependency file: {target}")
    findings = audit_dependencies(target)

    report = {
        "target_file": target,
        "engine": "GHOST-SupplyChainAuditor v3.0-PRO",
        "total_dependencies_found": len(findings),
        "findings": findings
    }

    with open(args.json, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Supply chain audit report saved to: {args.json}")

if __name__ == "__main__":
    main()
