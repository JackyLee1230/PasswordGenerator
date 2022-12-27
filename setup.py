import subprocess
import sys

packages = ["tk"]


def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tk"])


def main():
    subprocess.check_call([sys.executable, "-m", "pip",
                          "install", "--user", "--upgrade", "pip"])
    for package in packages:
        install(package)


main()
