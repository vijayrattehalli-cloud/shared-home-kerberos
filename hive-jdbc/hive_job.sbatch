#!/bin/bash
#SBATCH -J hive-query-jdk24
#SBATCH -N 4
#SBATCH -t 04:00:00
# The TGT is in $HOME/.krb5/krb5cc_hpc (shared FS); krb-credd keeps it fresh while
# this job is pending/running; TaskProlog exported KRB5CCNAME on every node.
set -euo pipefail
JAVA=/usr/lib/jvm/java-24/bin/java
CP=/opt/krb-hpc/hive-jdbc-jdk24-shim.jar:/opt/hive/jdbc/hive-jdbc-4.0.1-standalone.jar:/opt/krb-hpc/hpc-hive-krb24.jar
# Binary transport + fromSubject is required on JDK 24 (see README).
URL="jdbc:hive2://hs2.hadoop.example.mil:10000/default;principal=hive/_HOST@HPC.EXAMPLE.MIL;ssl=true;sslTrustStore=/etc/pki/java/hive-truststore.jks;kerberosAuthType=fromSubject"

srun --ntasks-per-node=1 bash -c 'klist -s && echo "$(hostname -s): TGT ok ($KRB5CCNAME)"'

# one query per node, e.g. partitioned extraction
export JAVA CP URL
srun --ntasks-per-node=1 bash -c '"$JAVA" -Djava.security.krb5.conf=/etc/krb5.conf -cp "$CP" \
     hpc.krb.HiveKerberosClient24 "$URL" \
     "SELECT current_user(), count(*) FROM sales.orders WHERE pmod(hash(order_id),$SLURM_NNODES)=$SLURM_NODEID"'

