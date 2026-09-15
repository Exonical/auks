FROM rockylinux/rockylinux:10 AS slurm-build

ARG SLURM_VERSION=26.05.4
ARG SLURM_SHA256=035f4b193d4de979ba5381beca206a50b6b886b2793b06f68a1ce7e67022b06a

RUN dnf -y install \
        dnf-plugins-core \
        epel-release \
    && dnf config-manager --set-enabled crb \
    && dnf -y install \
        bzip2 \
        curl \
        gcc \
        gcc-c++ \
        gzip \
        hwloc-devel \
        json-c-devel \
        libcurl-devel \
        libevent-devel \
        libjwt-devel \
        libuuid-devel \
        lz4-devel \
        make \
        ncurses-devel \
        numactl-devel \
        openssl-devel \
        pam-devel \
        perl \
        perl-devel \
        readline-devel \
        tar \
        xz-devel \
        zlib-devel \
    && dnf clean all

WORKDIR /tmp
RUN curl -fsSL "https://download.schedmd.com/slurm/slurm-${SLURM_VERSION}.tar.bz2" \
        -o "slurm-${SLURM_VERSION}.tar.bz2" \
    && echo "${SLURM_SHA256}  slurm-${SLURM_VERSION}.tar.bz2" | sha256sum -c - \
    && tar -xjf "slurm-${SLURM_VERSION}.tar.bz2"

WORKDIR /tmp/slurm-${SLURM_VERSION}
RUN ./configure \
        --prefix=/usr/local \
        --sysconfdir=/etc/slurm \
        --with-munge=no \
        --disable-pam \
        --with-yaml=no \
        --with-hwloc=no \
        --with-libcurl=no \
        --with-readline=no \
    && make -j"$(nproc)" \
    && make install

FROM rockylinux/rockylinux:10

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

RUN dnf -y install dnf-plugins-core \
    && dnf config-manager --set-enabled crb \
    && dnf -y install epel-release \
    && dnf -y install \
        autoconf \
        automake \
        bats \
        bison \
        diffutils \
        file \
        flex \
        gcc \
        gdb \
        krb5-devel \
        krb5-workstation \
        libtirpc \
        libtirpc-devel \
        libjwt \
        libtool \
        make \
        numactl-libs \
        procps-ng \
        shadow-utils \
        strace \
    && dnf clean all

COPY --from=slurm-build /usr/local /usr/local

COPY . auks

WORKDIR /auks

RUN autoreconf -fvi \
    && ./configure \
        --with-slurm=/usr/local \
        --with-slurm-lib=/usr/local/lib \
    && make clean \
    && make \
    && make install

COPY fixtures/krb5.conf /etc/krb5.conf
COPY fixtures/auks* /conf/
COPY fixtures/slurm.conf /etc/slurm/slurm.conf
COPY fixtures/plugstack.conf /etc/slurm/plugstack.conf
COPY fixtures/cgroup.conf /etc/slurm/cgroup.conf
COPY fixtures/renewer_script.sh /usr/local/bin/renewer_script.sh
COPY fixtures/entrypoint_*.sh /usr/local/bin/
RUN chmod 0750 /usr/local/bin/entrypoint_*.sh \
    && mkdir -p /var/cache/auks /var/log/slurm /var/spool/slurmctld /var/spool/slurmd \
    && useradd -r -u 990 -s /sbin/nologin slurm \
    && useradd -M -u 1234 user \
    && useradd -M -u 4321 admin \
    && chown -R slurm:slurm /var/spool/slurmctld /var/spool/slurmd /var/log/slurm

EXPOSE 12345/tcp
