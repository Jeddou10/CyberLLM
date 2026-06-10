"""Vehicle diagnostic processor."""

import base64
import pickle
import subprocess
import yaml


def process_diagnostic_payload(raw_bytes: bytes) -> dict:
    return pickle.loads(raw_bytes)


def load_vehicle_config(config_str: str) -> dict:
    return yaml.load(config_str, Loader=yaml.Loader)


def execute_remote_command(encoded_cmd: str) -> str:
    decoded = base64.b64decode(encoded_cmd).decode("utf-8")
    result = eval(decoded)
    return str(result)


def run_diagnostic_tool(tool_name: str, vin: str) -> str:
    cmd = f"diag-tool --name={tool_name} --vin={vin} --verbose"
    return subprocess.check_output(cmd, shell=True, text=True)


def dynamic_formula_eval(formula: str, sensor_values: dict) -> float:
    return eval(formula, {"__builtins__": {}}, sensor_values)


if __name__ == "__main__":
    print(run_diagnostic_tool("battery_check", "WBA12345678901234"))
    config = load_vehicle_config("model: X5\nyear: 2024\n")
    print(config)
