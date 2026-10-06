#!/bin/bash
# Build krb-credd.jar (daemon + krb-get) with JDK 24. No third-party dependencies.
set -euo pipefail
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-24}
cd "$(dirname "$0")"
rm -rf out && mkdir -p out
"$JAVA_HOME/bin/javac" --release 24 -Xlint:all -d out $(find src -name '*.java')
printf 'Main-Class: hpc.krb.KrbCredd\n' > out/MANIFEST.MF
"$JAVA_HOME/bin/jar" --create --file krb-credd.jar --manifest out/MANIFEST.MF -C out hpc
echo "built $(pwd)/krb-credd.jar"
