#!/bin/bash
# Build the JDK 24 Hive client and the driver shim.
#   ./build.sh /opt/hive/jdbc/hive-jdbc-4.0.1-standalone.jar
set -euo pipefail
DRIVER="${1:?usage: build.sh <hive-jdbc jar>}"
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-24}
cd "$(dirname "$0")"
rm -rf out && mkdir -p out
"$JAVA_HOME/bin/javac" --release 24 -d out src/hpc/krb/HiveKerberosClient24.java
"$JAVA_HOME/bin/jar" --create --file hpc-hive-krb24.jar -C out hpc
JAVA_HOME=$JAVA_HOME shim/build-shim.sh "$DRIVER"
echo "classpath: $(pwd)/shim/hive-jdbc-jdk24-shim.jar:$DRIVER:$(pwd)/hpc-hive-krb24.jar"
