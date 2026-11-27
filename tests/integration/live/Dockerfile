ARG SPLUNK_IMAGE
FROM ${SPLUNK_IMAGE}

USER root
# The base image provides the Python used by its bundled Ansible.
RUN microdnf install -y --setopt=install_weak_deps=0 openssh-server && microdnf clean all \
    && install -d -o root -g splunk -m 0750 /opt/splunk-ci \
    && install -d -m 0755 /run/sshd /tmp/defaults
COPY default.yml /tmp/defaults/default.yml
COPY sshd_config /etc/ssh/sshd_config_ci
USER ansible
RUN ansible-playbook --version
