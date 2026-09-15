#!/bin/bash

KADMIN="kadmin -p kadmin/admin -w password"
HOST_PRINCIPAL="host/$(hostname -f)@EXAMPLE.COM"

if ! $KADMIN list_principals | grep -Fx "$HOST_PRINCIPAL"
then
    $KADMIN add_principal -randkey "$HOST_PRINCIPAL"
fi

$KADMIN ktadd -k /etc/krb5.keytab "$HOST_PRINCIPAL"

dd if=/dev/urandom of=/etc/slurm/slurm.key bs=1024 count=1 status=none
chown slurm:slurm /etc/slurm/slurm.key
chmod 0600 /etc/slurm/slurm.key

install -d -o slurm -g slurm /var/spool/slurmctld /var/spool/slurmd /var/log/slurm

kinit -k -t /etc/krb5.keytab -c FILE:/tmp/krb5cc_0 "$HOST_PRINCIPAL"

slurmctld -Dvvv > /var/log/slurm/slurmctld.log 2>&1 &
slurmd -Dvvv > /var/log/slurm/slurmd.log 2>&1 &

for _ in $(seq 1 60)
do
    if scontrol ping >/dev/null 2>&1
    then
        break
    fi
    sleep 1
done

scontrol ping

if [ "$#" -gt 0 ]
then
    exec "$@"
fi

exec sleep infinity
