#!/usr/bin/env python3
# Copyright 2016-2017,2020,2025  Simon Arlott
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import datetime
import configparser
import fcntl
import hashlib
import os
import random
import re
import subprocess
import sys
import syslog
import traceback

LINK_RE = re.compile(r'^Link: <(?P<url>[^>]+)>;rel="up"$')
CN_RE = re.compile(r"Subject:.*? CN=([^\s,;/]+)")
SAN_RE = re.compile(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n")

home = os.environ["HOME"]
etcdir = os.path.join(home, "etc")


def cert_process(name, cfg):
	ari = ""

	if os.path.exists(cfg["req"]):
		request = False

		configured = cert_get_configured_names(name, cfg)

		if os.path.exists(cfg["cert"]):
			(ari, start, end) = cert_renewalinfo(name, cfg)

			if ari is not None and start is not None and end is not None:
				now = datetime.datetime.now(tz=datetime.timezone.utc)
				renew_at = start + datetime.timedelta(seconds=random.randrange((end - start).total_seconds()))
				next_run = now + datetime.timedelta(hours=cfg.getint("hours"))

				if now >= renew_at or end < next_run:
					syslog.syslog("{0}: will expire soon".format(name))
					request = True
			else:
				ari = ""

				with subprocess.Popen(["openssl", "x509", "-noout", "-checkend", str(86400 * cfg.getint("days")), "-in", cfg["cert"]],
						stdin=subprocess.DEVNULL,
						stdout=subprocess.DEVNULL,
						stderr=subprocess.DEVNULL) as proc:
					retcode = proc.wait(timeout=30)
					if retcode != 0:
						syslog.syslog("{0}: will expire soon".format(name))
						request = True

			existing = cert_get_existing_names(name, cfg)
			if configured - existing:
				syslog.syslog("{0}: has new names: {1}".format(name, configured - existing))

				if not configured & existing:
					ari = ""

				request = True
		elif not os.path.exists(os.path.dirname(cfg["cert"])):
			syslog.syslog("{0}: cert directory does not exist".format(name))
			return
		else:
			syslog.syslog("{0}: cert file does not exist".format(name))
			request = True

		csr_names = cert_get_request_names(name, cfg)
		if configured - csr_names:
			syslog.syslog("{0}: request is missing names: {1}".format(name, configured - csr_names))
			request = False
		elif csr_names - configured:
			syslog.syslog("{0}: request has extra names: {1}".format(name, csr_names - configured))
			request = False

		if request:
			syslog.syslog("{0}: requesting certificate".format(name))
			if cert_request(name, cfg, ari):
				syslog.syslog("{0}: certificate updated".format(name))


def cert_get_existing_names(name, cfg):
	names = set()

	with subprocess.Popen(["openssl", "x509", "-in", cfg["cert"], "-noout", "-text"],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			universal_newlines=True) as proc:
		(stdout, stderr) = proc.communicate()
		retcode = proc.wait(timeout=30)
		if retcode != 0:
			print("Error processing {0}, openssl x509 returned {1}".format(name, retcode))

	cn = CN_RE.search(stdout)
	if cn:
		names.add(cn.group(1))

	sans = SAN_RE.search(stdout, re.MULTILINE|re.DOTALL)
	if sans:
		for san in sans.group(1).split(", "):
			if san.startswith("DNS:"):
				names.add(san[4:])

	return names


def cert_get_request_names(name, cfg):
	names = set()

	with subprocess.Popen(["openssl", "req", "-in", cfg["req"], "-noout", "-text"],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			universal_newlines=True) as proc:
		(stdout, stderr) = proc.communicate()
		retcode = proc.wait(timeout=30)
		if retcode != 0:
			print("Error processing {0}, openssl req returned {1}".format(name, retcode))

	cn = CN_RE.search(stdout)
	if cn:
		names.add(cn.group(1))

	sans = SAN_RE.search(stdout, re.MULTILINE|re.DOTALL)
	if sans:
		for san in sans.group(1).split(", "):
			if san.startswith("DNS:"):
				names.add(san[4:])

	return names


def cert_get_configured_names(name, cfg):
	with open(cfg["config"], "r") as f:
		pass

	config = configparser.ConfigParser()
	config.read(cfg["config"])

	return set(config.sections())


def cert_renewalinfo(name, cfg):
	retcode = 0
	with subprocess.Popen(["/usr/local/lib/acme-tiny/acme_tiny.py",
				"--quiet",
				"--directory", cfg["directory"],
				"renewalinfo",
				"--account-key", cfg["account_key"],
				"--cert", cfg["cert"],
			],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			universal_newlines=True) as proc:
		(stdout, stderr) = proc.communicate(timeout=600)
		retcode = proc.wait(timeout=30)

	if retcode == 0:
		ari = None
		start = None
		end = None
		for line in stdout.splitlines():
			if line.startswith("OK: "):
				(ari, start, end) = line.split(" ")[1:4]
				if start.endswith("Z"):
					start = datetime.datetime.fromisoformat(start[:-1]).replace(tzinfo=datetime.timezone.utc)
				else:
					start = None
				if end.endswith("Z"):
					end = datetime.datetime.fromisoformat(end[:-1]).replace(tzinfo=datetime.timezone.utc)
				else:
					end = None

		syslog.syslog("{0}: renewal info: ari=\"{1}\" start=\"{2}\" end=\"{3}\"".format(name, ari, str(start), str(end)))
		return (ari, start, end)
	else:
		print("Error processing {0!r}, acme-tiny returned {1}\n{2}\n{3}".format(name, retcode, stdout, stderr))
		return (None, None, None)


def cert_request(name, cfg, ari=""):
	syslog.syslog("{0}...".format(name))

	try:
		os.unlink(cfg["cert"] + "-new")
	except FileNotFoundError:
		pass
	try:
		os.unlink(cfg["chain"] + "-new")
	except FileNotFoundError:
		pass
	try:
		os.unlink(cfg["fullchain"] + "-new")
	except FileNotFoundError:
		pass

	retcode = 0
	with subprocess.Popen(["/usr/local/lib/acme-tiny/acme_tiny.py",
				"--verbose",
				"--syslog", name,
				"--directory", cfg["directory"],
				"cert",
				"--account-key", cfg["account_key"],
				"--config", cfg["config"],
				"--req", cfg["req"],
				"--path", "C = US, O = Internet Security Research Group, CN = ISRG Root X1",
				"--ari", ari,
			],
			stdin=subprocess.DEVNULL,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			universal_newlines=True) as proc:
		(stdout, stderr) = proc.communicate(timeout=600)
		retcode = proc.wait(timeout=30)
		syslog.syslog("{0}: retcode={1}".format(name, retcode))

	if retcode == 0:
		ee_cert = ""
		issuer_cert = ""
		ee = True
		for line in stdout.splitlines():
			if line == "":
				continue

			if ee:
				ee_cert += line + "\n"
			else:
				issuer_cert += line + "\n"

			if line == "-----END CERTIFICATE-----":
				ee = False

		if not ee_cert or not issuer_cert:
			raise ValueError("Invalid certificate chain: " + repr(stdout))

		with open(cfg["cert"] + "-new", "w") as f:
			f.write(ee_cert)
		with open(cfg["chain"] + "-new", "w") as f:
			f.write(issuer_cert)
		with open(cfg["fullchain"] + "-new", "w") as f:
			f.write(ee_cert + issuer_cert)

		os.rename(cfg["chain"] + "-new", cfg["chain"])
		os.rename(cfg["fullchain"] + "-new", cfg["fullchain"])
		os.rename(cfg["cert"] + "-new", cfg["cert"])
		return True
	else:
		print("Error processing {0!r}, acme-tiny returned {1}\n{2}\n{3}".format(name, retcode, stdout, stderr))
		return False


def main():
	if len(sys.argv) != 2:
		print("Usage: acme-process <config>")
		return 0

	with open(os.path.join(etcdir, "process.lock"), "r+b") as f:
		fcntl.lockf(f, fcntl.LOCK_EX)

		cfg = configparser.ConfigParser()
		cfg.read(sys.argv[1])

		for cert_cfg in set(cfg.sections()):
			try:
				cert_process(cert_cfg, cfg[cert_cfg])
			except KeyboardInterrupt:
				raise
			except:
				print("Error processing {0!r}:".format(cert_cfg))
				traceback.print_exc()
				print()

	return 0


if __name__ == "__main__":
	sys.exit(main())
