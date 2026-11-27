ARG SPLUNK_IMAGE
FROM ${SPLUNK_IMAGE}

USER root
RUN microdnf install -y openssh-server python3 && microdnf clean all \
    && install -d -o root -g splunk -m 0750 /opt/splunk-ci \
    && install -d -m 0755 /run/sshd /tmp/defaults
COPY default.yml /tmp/defaults/default.yml
COPY sshd_config /etc/ssh/sshd_config_ci
USER ansible
