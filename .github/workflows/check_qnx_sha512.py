#!/usr/bin/env python3

##
## Author......: See docs/credits.txt
## License.....: MIT
##

# test-intel-qnx.yml uses these SHA512 vectors. check_descrypt.py also uses the device selector.

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


LEGACY = (
  ("@S@386d4be6fe9625c014b2486d8617ccfc521566be190d8a982b93698b99e0e3e3a18464281a514d5dda3ec5581389086f42b5dde023e934221bbe2e0106674cf7@129b6761", b"password"),
  ("@S@60653c9f515eb8480486450c82eaad67f894e2f4828b6340fa28f47b7c84cc2b8bc451e37396150a1ab282179c6fe4ca777a7c1a17511b5d83f0ce23ca28da5d@caa3cc118d2deb23", b"password"),
  ("@S,99@c6977abd2a945f9b45c0afff9f4f679524b9348f12bcf20a36b5b286f41d9f801cb9c883ad31073830b0d627abbe5925d0893e1daeac62d48799f0dc8efdd8eb@abcd1234abcd1234", b"3"),
  ("@S,100@a305c157dbb3ec42558799b2b02fa2036cd7fac5fe6f3ef932eb6504590f09abb90b97581a08e07e1b56d41c0956317f56d9c19e77e625447cdd1071500440b1@abcd1234abcd1234", b"3"),
  ("@S,111@57e31e7a28fa390a4b016ea6ef97d3827db4d24395a1e36dbcb029ab503d3658c450bca4244a2be1f0fa4ead24899dfd74decfa3f01d08e465b360f3917c7e18@abcd1234abcd1234", b"3"),
)

PUBLISHED = "@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159"


def standard(word, salt, iterations):
  value = hashlib.sha512(salt.encode("ascii") + word * (iterations + 1)).hexdigest()
  tag = "S" if iterations == 1000 else "S,%d" % iterations
  return "@%s@%s@%s" % (tag, value, salt)


def fixtures():
  lengths = (1, 3, 4, 7, 8, 15, 16, 31, 32, 55, 56, 63, 64, 95, 96, 110, 111, 112, 113, 115, 116, 119, 120, 127, 128, 129, 191, 192, 255, 256)
  words = [bytes(33 + index % 90 for index in range(length)) for length in lengths]
  words += [b"A\x00B", b"A\nB", b"A\xffB", "\u00e9\U0001f600".encode("utf-8")]
  targets = [(standard(word, salt, iterations), word) for salt in ("12345678", "123456789abcdef0")
             for iterations in (0, 1, 2, 127, 1000) for word in words]
  targets += LEGACY
  return list(dict.fromkeys(targets))


def cpu_device(binary, directory):
  command = [str(binary), "-I", "--machine-readable"]
  result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
  (directory / "backend.json").write_bytes(result.stdout)
  (directory / "backend.stderr.log").write_bytes(result.stderr)
  if result.returncode != 0:
    raise RuntimeError("backend inventory failed")
  inventory = json.loads(result.stdout)
  matches = []
  for platform in inventory.get("OpenCLInfo", {}).get("Platforms", []):
    if "intel" not in platform.get("Vendor", "").casefold():
      continue
    for device in platform.get("BackendDevices", []):
      if device.get("Type") == "CPU":
        matches.append(device)
  if len(matches) != 1:
    raise RuntimeError("this check requires one CPU through the Intel CPU OpenCL runtime")
  print("Intel CPU OpenCL:", json.dumps(matches[0]), flush=True)
  return matches[0]["DeviceID"]


def run(binary, directory, device, force):
  targets = fixtures()
  words = list(dict.fromkeys(word for _, word in targets))
  (directory / "hashes.txt").write_text("\n".join(value for value, _ in targets) + "\n")
  (directory / "words.hex").write_text("\n".join(word.hex() for word in words) + "\n")
  (directory / "wrong.hex").write_text(b"wrong-password-control".hex() + "\n")
  expected = {(value, word.hex()) for value, word in targets}
  (directory / "expected.json").write_text(json.dumps(sorted(expected), indent=2) + "\n")
  opts = [str(binary), "-m", "19200", "-a", "0", "-D", "1", "-d", str(device), "--hex-wordlist",
          "--potfile-disable", "--logfile-disable", "--restore-disable", "--status", "--status-json",
          "--runtime", "180", "--cache-path", str(directory / "cache"), "--outfile-format", "1,3"]
  if force:
    opts.append("--force")
  report = []
  for label, candidates, selected in (("forward", words, expected), ("reverse", words[::-1], expected), ("negative", [b"wrong-password-control"], set())):
    wordfile = directory / (label + ".hex")
    wordfile.write_text("\n".join(word.hex() for word in candidates) + "\n")
    outfile = directory / (label + ".cracked")
    command = opts + ["--outfile", str(outfile), str(directory / "hashes.txt"), str(wordfile)]
    (directory / (label + "-command.json")).write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
    (directory / (label + ".log")).write_bytes(result.stdout + result.stderr)
    recovered = [tuple(line.split(":", 1)) for line in outfile.read_text().splitlines()] if outfile.exists() else []
    ok = result.returncode == (0 if selected else 1) and set(recovered) == selected and len(recovered) == len(selected)
    report.append({"case": label, "returncode": result.returncode, "recovered": len(recovered), "expected": len(selected), "passed": ok})
    print(label, json.dumps(report[-1]), flush=True)
    if not ok:
      print((result.stdout + result.stderr).decode("utf-8", "replace"), flush=True)
  (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
  return 0 if all(row["passed"] for row in report) else 1


def inline_check(directory, device, force):
  results = []
  for selected_force in ((False, True) if force else (False,)):
    label = "inline-force" if selected_force else "inline-no-force"
    command = ["./hashcat", "-m", "19200", "-a", "3", "--hex-charset", "-D", "1", "-d", str(device),
               "--potfile-disable", "--logfile-disable", "--restore-disable", "--status", "--status-json"]
    if selected_force:
      command.append("--force")
    # Keep the literal mask distinct from the executable's filename.
    command += [PUBLISHED, b"hashcat".hex()]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    (directory / (label + "-command.json")).write_text(json.dumps(command, indent=2) + "\n")
    (directory / (label + ".log")).write_bytes(result.stdout + result.stderr)
    states = []
    for line in result.stdout.splitlines():
      try:
        data = json.loads(line)
      except ValueError:
        continue
      if isinstance(data, dict) and "recovered_hashes" in data:
        states.append(data)
    cracked = result.returncode == 0 and states and states[-1]["recovered_hashes"] == [1, 1]
    guarded = result.returncode == 253 and b"Skipping (hash-mode 19200)" in result.stdout + result.stderr
    results.append({"force": selected_force, "returncode": result.returncode, "cracked": bool(cracked), "guarded": guarded})
    print(label, json.dumps(results[-1]), flush=True)
    if not cracked and not (force and not selected_force and guarded):
      raise RuntimeError("published inline vector did not crack or reach the expected diagnostic guard")
  (directory / "inline-results.json").write_text(json.dumps(results, indent=2) + "\n")


def main():
  parser = argparse.ArgumentParser(description="Check QNX SHA512 standard and legacy vectors on Intel CPU OpenCL")
  parser.add_argument("--diagnostic-force", action="store_true", help="bypass the existing runtime exclusion for diagnosis")
  parser.add_argument("--output", type=Path, default=Path("qnx-intel-results"))
  parser.add_argument("--allow-other-opencl", action="store_true", help=argparse.SUPPRESS)
  args = parser.parse_args()
  binary = Path("hashcat").resolve()
  args.output.mkdir()
  (args.output / "cache").mkdir()
  device = "1" if args.allow_other_opencl else cpu_device(binary, args.output)
  inline_check(args.output, device, args.diagnostic_force)
  return run(binary, args.output.resolve(), device, args.diagnostic_force)


if __name__ == "__main__":
  raise SystemExit(main())
