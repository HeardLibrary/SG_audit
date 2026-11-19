import boto3
import time
from botocore.exceptions import ClientError

# Ports that should almost NEVER be exposed to 0.0.0.0/0
HIGH_RISK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL/Aurora",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "Alt HTTP/Admin",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def get_instance_name(tags):
    if not tags:
        return "Unnamed"
    for tag in tags:
        if tag["Key"] == "Name":
            return tag["Value"]
    return "Unnamed"


def check_shady_rules(rules, direction="Inbound"):
    findings = []
    for rule in rules:
        protocol = rule.get("IpProtocol", "-1")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        # Collect all CIDRs in this rule
        cidrs = [ip["CidrIp"] for ip in rule.get("IpRanges", [])] + [
            ip["CidrIpv6"] for ip in rule.get("Ipv6Ranges", [])
        ]
        is_public = any(c in PUBLIC_CIDRS for c in cidrs)

        if not is_public:
            continue

        # 1. All traffic open to the world
        if protocol == "-1":
            if direction == "Inbound":
                findings.append(
                    "CRITICAL [Inbound]: ALL traffic (-1) open to 0.0.0.0/0"
                )
            else:
                findings.append(
                    "INFO [Outbound]: Unrestricted egress (ALL traffic to 0.0.0.0/0 - AWS default, tighten for strict compliance)"
                )
            continue

        # 2. Port range checks
        if from_port is not None and to_port is not None:
            if direction == "Inbound":
                # Check if any high-risk port falls inside the rule's range
                exposed_sensitive = [
                    f"{p} ({name})"
                    for p, name in HIGH_RISK_PORTS.items()
                    if from_port <= p <= to_port
                ]
                if exposed_sensitive:
                    findings.append(
                        f"HIGH [Inbound]: Sensitive port(s) {', '.join(exposed_sensitive)} open to {cidrs}"
                    )
                elif (to_port - from_port) > 10:
                    findings.append(
                        f"MEDIUM [Inbound]: Wide port range {from_port}-{to_port} ({protocol}) open to {cidrs}"
                    )
                elif from_port not in (80, 443):
                    findings.append(
                        f"LOW [Inbound]: Non-standard port {from_port}-{to_port} ({protocol}) open to public"
                    )
            else:
                # Outbound non-standard ports to 0.0.0.0/0
                if not (from_port in (80, 443, 53, 123) and from_port == to_port):
                    findings.append(
                        f"LOW [Outbound]: Port {from_port}-{to_port} ({protocol}) open to 0.0.0.0/0"
                    )

    return findings


def get_listening_ports_via_ssm(ssm_client, instance_id, platform):
    """Queries the OS via AWS SSM to see which ports are actually listening."""
    try:
        if platform == "windows":
            doc_name = "AWS-RunPowerShellScript"
            commands = [
                "Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique"
            ]
        else:
            doc_name = "AWS-RunShellScript"
            commands = [
                "ss -tulnp | awk 'NR>1 {print $5}' | grep -oE '[0-9]+$' | sort -nu"
            ]

        resp = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName=doc_name,
            Parameters={"commands": commands},
        )
        command_id = resp["Command"]["CommandId"]

        # Wait briefly for command execution
        for _ in range(10):
            time.sleep(1.5)
            output = ssm_client.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )
            if output["Status"] in ("Success", "Failed", "TimedOut", "Cancelled"):
                break

        if output["Status"] == "Success":
            ports = [
                int(p.strip())
                for p in output["StandardOutputContent"].splitlines()
                if p.strip().isdigit()
            ]
            return sorted(list(set(ports)))
        return f"SSM Command {output['Status']}"
    except ClientError as e:
        if "InvalidInstanceId" in str(e):
            return "Not connected to SSM (Agent offline or missing IAM role)"
        return f"SSM Error: {e.response['Error']['Message']}"


def audit_account(region_name=None):
    session = boto3.Session(region_name=region_name)
    ec2 = session.client("ec2")
    ssm = session.client("ssm")
    current_region = session.region_name

    print(f"\n{'='*70}")
    print(f" AWS SECURITY GROUP & PORT AUDIT | Region: {current_region}")
    print(f"{'='*70}\n")

    # 1. Fetch all Security Groups
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    sg_map = {sg["GroupId"]: sg for sg in sgs}
    attached_sg_ids = set()

    # 2. Fetch all EC2 Instances
    reservations = ec2.describe_instances()["Reservations"]
    instances = [
        inst for res in reservations for inst in res.get("Instances", [])
    ]

    print(f"Found {len(sgs)} Security Groups and {len(instances)} EC2 Instances.\n")

    # 3. Audit each EC2 Instance
    for inst in instances:
        inst_id = inst["InstanceId"]
        name = get_instance_name(inst.get("Tags"))
        state = inst["State"]["Name"]
        platform = inst.get("Platform", "linux")
        inst_sgs = inst.get("SecurityGroups", [])

        print(f"EC2 Instance: {name} ({inst_id}) | State: {state} | OS: {platform}")
        print("-" * 70)

        allowed_inbound_ports = set()
        all_shady_findings = []

        for sg_ref in inst_sgs:
            sg_id = sg_ref["GroupId"]
            attached_sg_ids.add(sg_id)
            sg_detail = sg_map.get(sg_id, {})
            sg_name = sg_detail.get("GroupName", "Unknown")

            print(f"  -> Attached SG: {sg_name} ({sg_id})")

            # Collect allowed inbound ports
            for rule in sg_detail.get("IpPermissions", []):
                if rule.get("IpProtocol") == "-1":
                    allowed_inbound_ports.add("ALL")
                elif "FromPort" in rule and "ToPort" in rule:
                    if rule["FromPort"] == rule["ToPort"]:
                        allowed_inbound_ports.add(rule["FromPort"])
                    else:
                        allowed_inbound_ports.add(
                            f"{rule['FromPort']}-{rule['ToPort']}"
                        )

            # Check shady rules
            in_findings = check_shady_rules(
                sg_detail.get("IpPermissions", []), "Inbound"
            )
            out_findings = check_shady_rules(
                sg_detail.get("IpPermissionsEgress", []), "Outbound"
            )
            for f in in_findings + out_findings:
                all_shady_findings.append(f"[{sg_id}] {f}")

        # Compare allowed SG ports vs actually listening OS ports
        print(f"  Allowed Inbound Ports (via SGs): {sorted(allowed_inbound_ports, key=str)}")
        if state == "running":
            listening = get_listening_ports_via_ssm(ssm, inst_id, platform)
            print(f"  Actually Listening Ports (OS):   {listening}")
        else:
            print("  Actually Listening Ports (OS):   Skipped (Instance not running)")

        if all_shady_findings:
            print("  Shady / Risky Rules Detected:")
            for finding in all_shady_findings:
                print(f"     * {finding}")
        else:
            print("  Shady / Risky Rules Detected:    None")
        print()

    # 4. Report Unattached (Orphaned) Security Groups & Audit Them Too
    unattached = [sg for sg_id, sg in sg_map.items() if sg_id not in attached_sg_ids]
    print(f"{'='*70}")
    print(f" UNATTACHED SECURITY GROUPS ({len(unattached)})")
    print(f"{'='*70}")
    for sg in unattached:
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]
        findings = check_shady_rules(
            sg.get("IpPermissions", []), "Inbound"
        ) + check_shady_rules(sg.get("IpPermissionsEgress", []), "Outbound")
        print(f"  - {sg_name} ({sg_id}) | VPC: {sg.get('VpcId', 'EC2-Classic')}")
        for f in findings:
            print(f"      * {f}")


if __name__ == "__main__":
    # Leave None to use CloudShell's default region, or pass e.g. "us-east-1"
    audit_account(region_name=None)