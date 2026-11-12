import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", required=True)
    args = parser.parse_args()
    subprocess.run("rsync -a /srv/data " + args.dest, shell=True)


if __name__ == "__main__":
    main()
