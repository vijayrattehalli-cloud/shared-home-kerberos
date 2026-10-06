#!/bin/bash
# Build hive-jdbc-jdk24-shim.jar against YOUR Hive JDBC driver jar.
#
#   ./build-shim.sh /opt/hive/jdbc/hive-jdbc-4.0.1-standalone.jar
#
# Output: hive-jdbc-jdk24-shim.jar  (list it first on the classpath)
set -euo pipefail
DRIVER="${1:?usage: build-shim.sh <hive-jdbc jar> [extra classpath]}"
EXTRA="${2:-}"
JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/java-24}
cd "$(dirname "$0")"

if unzip -l "$DRIVER" | grep -q 'org/apache/hive/org/apache/thrift/transport/TTransport.class'; then
    THRIFT=org.apache.hive.org.apache.thrift        # hive-jdbc-*-standalone.jar (shaded)
elif unzip -l "$DRIVER" | grep -q 'org/apache/hive/service/auth/TSubjectAssumingTransport.class'; then
    THRIFT=org.apache.thrift                        # thin hive-jdbc/hive-service jar + libthrift
else
    echo "TSubjectAssumingTransport not found in $DRIVER -- is this a Hive JDBC driver?" >&2
    exit 1
fi
unzip -l "$DRIVER" | grep -q 'org/apache/hadoop/hive/thrift/TFilterTransport.class' || [[ -n "$EXTRA" ]] || {
    echo "TFilterTransport not in $DRIVER; pass the hive-shims jar as 2nd argument" >&2; exit 1; }

rm -rf out && mkdir -p out/src/org/apache/hive/service/auth out/classes
sed "s/@THRIFT@/${THRIFT}/g" TSubjectAssumingTransport.java.in \
    > out/src/org/apache/hive/service/auth/TSubjectAssumingTransport.java
"$JAVA_HOME/bin/javac" --release 24 -cp "$DRIVER${EXTRA:+:$EXTRA}" -d out/classes \
    out/src/org/apache/hive/service/auth/TSubjectAssumingTransport.java
"$JAVA_HOME/bin/jar" --create --file hive-jdbc-jdk24-shim.jar -C out/classes org
echo "built $(pwd)/hive-jdbc-jdk24-shim.jar (thrift package: $THRIFT)"
